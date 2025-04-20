import argparse
import base64
import logging
import os
import re
import time
from io import StringIO
from typing import Optional, Dict

# Local imports
from ssh_runner import SSHRunner
from utils import decode_if_base64, mask_secrets

log = logging.getLogger(__name__)

# --- Constants ---
REQUIRED_CORE_COMMANDS = ["docker", "systemctl", "mkdir", "chmod", "chown", "mv", "rm", "ln", "tee", "command", "whoami"]
NGINX_COMMANDS = ["nginx"] # Only needed if Nginx isn't skipped

class VpsDeployer:
    """Orchestrates the deployment steps using an SSHRunner."""

    def __init__(self, args: argparse.Namespace, secrets: Dict[str, Optional[str]], runner: SSHRunner):
        self.args = args
        self.secrets = secrets
        self.runner = runner # Use the provided SSHRunner instance

    def run(self):
        """Executes the full deployment workflow."""
        log.info("--- Starting Deployment Workflow ---")
        try:
            self._check_dependencies()
            self._ensure_directories()

            if not self.args.nginx_skip:
                if not self.args.ssl_skip:
                    self._deploy_ssl()
                else:
                    log.info("Skipping SSL file deployment as per --ssl-skip flag.")
                self._deploy_nginx_config()
            else:
                log.info("Skipping Nginx and SSL deployment as per --nginx-skip flag.")

            self._deploy_docker()

            if not self.args.nginx_skip:
                self._validate_nginx()
            else:
                log.info("Skipping Nginx validation and reload.")

            self._cleanup_images()

            log.success("--- Deployment Workflow Completed Successfully! ---")
            deploy_proto = "https" if not self.args.nginx_skip and not self.args.ssl_skip else "http"
            log.info(f"Application '{self.args.image_name}' deployed using image '{self.args.image_url}'.")
            if not self.args.nginx_skip:
                log.info(f"Expected to be accessible at: {deploy_proto}://{self.args.domain}")
            else:
                 log.info("Nginx setup was skipped.")

        except (RuntimeError, ValueError, IOError) as e:
            log.critical(f"DEPLOYMENT STEP FAILED: {e.__class__.__name__}: {e}")
            raise # Re-raise the caught exception

    def _check_dependencies(self):
        """Checks for essential commands and sudo access."""
        log.info("Checking remote host dependencies...")
        all_found = True
        commands_to_check = REQUIRED_CORE_COMMANDS + (NGINX_COMMANDS if not self.args.nginx_skip else [])

        for cmd in commands_to_check:
            result = self.runner.run(f"command -v {cmd}", warn=True, capture=True, hide=True)
            if not result or not result.ok:
                log.error(f"Required command '{cmd}' not found.")
                all_found = False

        if not all_found:
            raise RuntimeError("Missing remote dependencies. Please install them.")

        log.info("Checking sudo access...")
        self.runner.sudo("whoami", hide=True, error_msg_prefix="Sudo check failed")
        log.info("Dependency check completed.")


    def _ensure_directories(self):
        """Ensures necessary directories exist."""
        log.info("Ensuring required directories exist...")
        nginx_dirs = ["/etc/nginx/ssl", "/etc/nginx/sites-available", "/etc/nginx/sites-enabled"]
        dirs_to_create = nginx_dirs if not self.args.nginx_skip else []
        if not dirs_to_create: return

        dirs_str = " ".join(dirs_to_create)
        self.runner.sudo(f"mkdir -p {dirs_str}", error_msg_prefix="Failed to create directories")
        log.info(f"Directories checked/created: {dirs_str}")


    def _upload_content(self, content: str, remote_path: str, owner: str = "root", 
                        group: str = "root", mode: str = "644", sensitive: bool = False):
        """Uploads string content via SSHRunner."""
        remote_dir = os.path.dirname(remote_path)
        remote_filename = os.path.basename(remote_path)
        remote_tmp_path = f"/tmp/{remote_filename}.{int(time.time())}.tmp"

        if sensitive:
            log.info(f"Uploading sensitive content to {remote_path} (via temp file) mode={mode} owner={owner}:{group}")
        else:
            log.info(f"Uploading content to {remote_path} (via {remote_tmp_path}) mode={mode} owner={owner}:{group}")
            
        try:
            self.runner.put(StringIO(content), remote_tmp_path, sensitive=sensitive)
            self.runner.sudo(f"mkdir -p {remote_dir}", error_msg_prefix=f"Failed ensure dir {remote_dir}")
            self.runner.sudo(f"mv {remote_tmp_path} {remote_path}", error_msg_prefix="Failed to move file")
            self.runner.sudo(f"chown {owner}:{group} {remote_path}", error_msg_prefix="Failed to set owner")
            self.runner.sudo(f"chmod {mode} {remote_path}", error_msg_prefix="Failed to set mode")
            log.info(f"Successfully uploaded and configured {remote_path}")
        except (IOError, RuntimeError) as e:
            # Cleanup handled within _run_remote_cmd or put's exception
             log.error(f"Upload failed for {remote_path}. See previous errors.")
             self.runner.sudo(f"rm -f {remote_tmp_path}", warn=True, hide=True) # Attempt cleanup
             raise RuntimeError(f"Failed to upload content to {remote_path}") from e


    def _deploy_ssl(self):
        """Deploys SSL certificate and key."""
        log.info("Deploying SSL certificate and key...")
        cert_path = f"/etc/nginx/ssl/{self.args.domain}.crt"
        key_path = f"/etc/nginx/ssl/{self.args.domain}.key"

        cert_content = self.secrets.get("SECRET_SSL_CERT")
        key_content = self.secrets.get("SECRET_SSL_KEY")
        if not cert_content or not key_content:
            raise ValueError("SSL Cert or Key secret is missing.")
            
        final_cert = decode_if_base64(cert_content)
        final_key = decode_if_base64(key_content)
        if not final_cert or not final_key:
            raise ValueError("SSL Cert or Key content is empty after decode.")

        # Use _upload_content with sensitivity flag
        self._upload_content(final_cert, cert_path, mode="644", sensitive=True)
        self._upload_content(final_key, key_path, mode="600", sensitive=True)
        log.success("SSL certificate and key deployed.")


    def _deploy_nginx_config(self):
        """Deploys Nginx configuration."""
        log.info("Deploying Nginx configuration...")
        conf_b64 = self.secrets.get("VAR_NGINX_CONF_B64")
        if not conf_b64: raise ValueError("Nginx config Base64 missing.")

        try:
            conf_content = base64.b64decode(conf_b64).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Invalid Base64 Nginx config: {e}") from e

        conf_available_path = f"/etc/nginx/sites-available/{self.args.domain}.conf"
        conf_enabled_path = f"/etc/nginx/sites-enabled/{self.args.domain}.conf"

        # Use sensitive=True since config might contain secrets
        self._upload_content(conf_content, conf_available_path, mode="644", sensitive=True)
        self.runner.sudo(f"ln -sf {conf_available_path} {conf_enabled_path}",
                       error_msg_prefix="Failed to enable Nginx site (symlink)")
        log.success("Nginx configuration deployed and enabled.")


    def _deploy_docker(self):
        """Handles Docker image pull and container deployment."""
        container_name = re.sub(r'[^a-zA-Z0-9_.-]', '-', self.args.image_name) + "-container"
        log.info(f"Starting Docker deployment: {self.args.image_url} -> {container_name}")

        self.runner.run(f"docker pull {self.args.image_url}", hide=False, pty=False,
                      error_msg_prefix="Failed to pull Docker image")

        log.info(f"Stopping/removing old container '{container_name}'...")
        self.runner.run(f"docker stop {container_name}", warn=True, hide=True)
        self.runner.run(f"docker rm {container_name}", warn=True, hide=True)
        log.info("Old container removed (if existed).")
        time.sleep(2)

        log.info(f"Starting new container '{container_name}'...")
        port_mapping = f"127.0.0.1:{self.args.container_port}:{self.args.container_internal_port}"
        run_cmd = (
            f"docker run -d --name {container_name} --restart unless-stopped "
            f"-p {port_mapping} --log-opt max-size=10m --log-opt max-file=3 "
            f"{self.args.image_url}"
        )
        result = self.runner.run(run_cmd, capture=True, hide=True,
                               error_msg_prefix="Failed to start Docker container")

        if result and result.stdout:
             container_id = result.stdout.strip()[:12]
             log.success(f"Container '{container_name}' started. ID: {container_id}")
             time.sleep(3)
             status_result = self.runner.run(f"docker ps -f id={container_id} --format '{{{{.Status}}}}'",
                                           capture=True, hide=True, warn=True)
             if status_result and status_result.stdout and "Up" in status_result.stdout:
                  log.info(f"Container confirmed running.")
             else:
                  status = status_result.stdout.strip() if status_result else "Unknown"
                  log.warning(f"Container started but status is '{status}'. Check logs.")
                  self.runner.run(f"docker logs {container_name}", hide=False, warn=True)
        else:
             # Error was already logged by _run_remote_cmd which raised RuntimeError
             self.runner.run(f"docker logs {container_name}", hide=False, warn=True) # Attempt log retrieval
             raise RuntimeError("Failed to start container or get ID.")


    def _validate_nginx(self):
        """Validates Nginx config and reloads service."""
        log.info("Validating Nginx configuration...")
        result = self.runner.sudo("nginx -t", hide=True, warn=True, pty=False, capture=True,
                                error_msg_prefix="Nginx syntax check command failed")
        if result and result.ok and "test is successful" in result.stderr:
            log.info("Nginx config test successful.")
            self.runner.sudo("systemctl reload nginx",
                           error_msg_prefix="Failed to reload Nginx service")
            log.success("Nginx reloaded successfully.")
        elif result:
            log.critical("Nginx configuration test FAILED!")
            raise RuntimeError("Nginx validation failed. See logs for details.")
        else: # Should have been raised by _run_remote_cmd
             raise RuntimeError("Nginx syntax check command failed to execute.")


    def _cleanup_images(self):
        """Cleans up unused Docker images."""
        prune_filter = self.args.docker_prune_filter
        log.info(f"Cleaning up Docker images (filter: '{prune_filter}')...")
        cmd = f"docker image prune -af --filter \"{prune_filter}\""
        self.runner.run(cmd, hide=True, warn=True, # Non-critical
                      error_msg_prefix="Docker image prune failed")
        log.info("Docker image cleanup command executed.")