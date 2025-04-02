#!/usr/bin/env python3
import argparse
import base64
import logging
import os
import sys
import time
import tempfile
import getpass
from io import StringIO

from fabric import Connection
from invoke import UnexpectedExit

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)-5s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger(__name__)

# --- Helper Functions ---
def is_likely_base64(value: str) -> bool:
    """Checks if a string is likely Base64 encoded and not a PEM header."""
    if not value or not isinstance(value, str):
        return False
    # Check for base64 chars, potential whitespace/newlines, potential padding, AND absence of PEM header
    pattern = r'^[A-Za-z0-9+/=\n\r\s]+$'
    if re.match(pattern, value) and '-----BEGIN' not in value:
        try:
            base64.b64decode(value.strip(), validate=True)
            return True
        except Exception:
            return False
    return False

def decode_if_base64(value: str) -> str:
    """Decodes value if it's Base64, otherwise returns original."""
    if is_likely_base64(value):
        log.debug("Value appears to be Base64 encoded, decoding...")
        try:
            return base64.b64decode(value.strip()).decode('utf-8')
        except Exception as e:
            log.warning(f"Base64 decoding failed: {e}. Using raw value.")
            return value
    return value

def write_temp_key_file(key_content: str) -> str:
    """Writes SSH key content to a temporary file with secure permissions."""
    # Use tempfile for secure temporary file creation
    fd, temp_key_path = tempfile.mkstemp()
    log.debug(f"Writing SSH key to temporary file: {temp_key_path}")
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(key_content)
        os.chmod(temp_key_path, 0o600) # Set permissions to 600
        return temp_key_path
    except Exception as e:
        os.remove(temp_key_path) # Clean up if error occurs
        raise IOError(f"Failed to write temporary SSH key file: {e}") from e

# --- Deployment Steps ---

def ensure_directories(c: Connection):
    """Ensures necessary directories exist on the remote host."""
    log.info("Ensuring required directories exist...")
    dirs_to_create = "/etc/nginx/ssl /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/conf.d"
    try:
        c.sudo(f"mkdir -p {dirs_to_create}", hide=True)
        log.info("Directories checked/created.")
    except UnexpectedExit as e:
        log.error(f"Failed to create directories: {e.result.stderr.strip()}")
        raise

def deploy_ssl_files(c: Connection, domain: str, cert_content: str, key_content: str):
    """Deploys SSL certificate and key to the remote host."""
    log.info("Deploying SSL certificate and key...")
    cert_path = f"/etc/nginx/ssl/{domain}.crt"
    key_path = f"/etc/nginx/ssl/{domain}.key"

    # Decode content if needed
    final_cert_content = decode_if_base64(cert_content)
    final_key_content = decode_if_base64(key_content)

    try:
        # Use StringIO to pipe content to tee, avoiding temp files for content
        log.debug(f"Writing SSL certificate to {cert_path}...")
        c.put(StringIO(final_cert_content), f"/tmp/{domain}.crt.tmp")
        c.sudo(f"mv /tmp/{domain}.crt.tmp {cert_path}", hide=True)
        c.sudo(f"chmod 644 {cert_path}", hide=True)

        log.debug(f"Writing SSL key to {key_path}...")
        c.put(StringIO(final_key_content), f"/tmp/{domain}.key.tmp")
        c.sudo(f"mv /tmp/{domain}.key.tmp {key_path}", hide=True)
        c.sudo(f"chmod 600 {key_path}", hide=True) # Secure permissions
        log.info("SSL files deployed and permissions set.")
    except Exception as e: # Catch broader exceptions including potential put/mv/chmod failures
        log.error(f"Failed during SSL file deployment: {e}")
        # Attempt cleanup of temp files
        c.sudo(f"rm -f /tmp/{domain}.crt.tmp /tmp/{domain}.key.tmp", warn=True, hide=True)
        raise

def deploy_nginx_config(c: Connection, domain: str, nginx_conf_b64: str):
    """Deploys Nginx configuration file and enables the site."""
    log.info("Deploying Nginx configuration...")
    conf_path = f"/etc/nginx/sites-available/{domain}.conf"
    enabled_path = f"/etc/nginx/sites-enabled/{domain}.conf"

    try:
        nginx_conf_content = base64.b64decode(nginx_conf_b64).decode('utf-8')
        log.debug(f"Writing Nginx config to {conf_path}...")
        c.put(StringIO(nginx_conf_content), f"/tmp/{domain}.conf.tmp")
        c.sudo(f"mv /tmp/{domain}.conf.tmp {conf_path}", hide=True)

        log.info(f"Enabling Nginx site by linking {conf_path} to {enabled_path}...")
        c.sudo(f"ln -sf {conf_path} {enabled_path}", hide=True)
        log.info("Nginx configuration file deployed and linked.")
    except base64.binascii.Error as e:
        log.error(f"Failed to decode Base64 Nginx config: {e}")
        raise
    except Exception as e:
        log.error(f"Failed during Nginx config deployment: {e}")
        c.sudo(f"rm -f /tmp/{domain}.conf.tmp", warn=True, hide=True)
        raise

def deploy_docker_container(c: Connection, image_url: str, image_name: str, container_port: str):
    """Pulls image, stops/removes old container, starts new one."""
    container_name = f"{image_name}-container" # Using suffix decided earlier
    log.info(f"Preparing Docker deployment for image: {image_url}")

    # Pull Image
    log.info("Pulling Docker image...")
    try:
        # Run without sudo unless Docker requires it for the user
        c.run(f"docker pull {image_url}", hide=False) # Show pull progress
        log.info("Docker image pulled successfully.")
    except UnexpectedExit as e:
        log.error(f"Failed to pull Docker image '{image_url}': {e.result.stderr.strip()}")
        log.error("Check registry access, image name/tag, and Docker daemon status on remote host.")
        raise

    # Stop and Remove Old Container
    log.info(f"Attempting to stop and remove existing container '{container_name}' (if it exists)...")
    # Run stop/rm with warn=True to prevent failure if container doesn't exist
    c.run(f"docker stop {container_name}", warn=True, hide=True)
    c.run(f"docker rm {container_name}", warn=True, hide=True)
    log.debug(f"Stop/remove commands executed for '{container_name}'.")
    time.sleep(2) # Short pause

    # Run New Container
    log.info(f"Starting new container '{container_name}' from {image_url}...")
    # Adjust internal port (after second colon) if needed: :80 means container listens on 80
    docker_run_cmd = (
        f"docker run -d "
        f"--name {container_name} "
        f"--restart unless-stopped "
        f"-p 127.0.0.1:{container_port}:80 "
        f"--log-opt max-size=10m --log-opt max-file=3 "
        f"{image_url}"
    )
    try:
        result = c.run(docker_run_cmd, hide=True)
        log.info(f"Container '{container_name}' started successfully. Container ID: {result.stdout.strip()[:12]}")
    except UnexpectedExit as e:
        log.error(f"Failed to start new Docker container '{container_name}'!")
        log.error(f"Command failed: {docker_run_cmd}")
        log.error(f"Error Output: {e.result.stderr.strip()}")
        log.error("Common causes: Port conflict, resource limits, invalid image, Docker daemon issues.")
        # Attempt to get logs, even if start failed
        log.info(f"Attempting to check logs for possibly failed container '{container_name}':")
        c.run(f"docker logs {container_name}", warn=True, hide=False) # Show logs if available
        raise

def validate_and_reload_nginx(c: Connection):
    """Validates Nginx config and reloads the service."""
    log.info("Validating Nginx configuration...")
    try:
        # Run nginx -t. Capture output. hide=True suppresses command echo, pty=False needed for clean output capture sometimes
        result = c.sudo("nginx -t", hide=True, warn=True, pty=False)
        if result.ok and "test is successful" in result.stderr: # Nginx often prints test results to stderr
            log.info("Nginx configuration test successful.")
            log.info("Reloading Nginx service...")
            c.sudo("systemctl reload nginx", hide=True)
            log.info("Nginx reloaded successfully.")
        else:
            log.error("Nginx configuration test failed!")
            log.error("Output of 'nginx -t':")
            # Print both stdout and stderr for complete diagnosis
            if result.stdout: log.error(f"STDOUT:\n{result.stdout.strip()}")
            if result.stderr: log.error(f"STDERR:\n{result.stderr.strip()}")
            raise RuntimeError("Nginx configuration validation failed.")
    except UnexpectedExit as e:
        # This might catch the sudo call failing itself, or if nginx -t has non-zero exit code
        log.error("Failed to execute Nginx command (check sudo permissions?).")
        log.error(f"Command: {e.result.command}")
        log.error(f"Error Output: {e.result.stderr.strip()}")
        raise

def cleanup_docker_images(c: Connection):
    """Cleans up unused Docker images."""
    log.info("Cleaning up unused Docker images (older than 1 hour)...")
    try:
        # warn=True ensures failure doesn't stop the whole script if cleanup is non-critical
        c.run("docker image prune -af --filter 'until=1h'", warn=True, hide=True)
        log.info("Docker image cleanup command executed.")
    except UnexpectedExit as e:
        log.warning(f"Docker image prune command failed: {e.result.stderr.strip()}")


# --- Main Execution ---
def main():
    start_time = time.time()
    log.info(f"--- Python VPS Deployment Script Started ---")

    parser = argparse.ArgumentParser(description="Deploy Docker container to VPS with Nginx.")
    # Arguments matching action inputs
    parser.add_argument("--host", required=True, help="VPS hostname or IP address.")
    parser.add_argument("--user", required=True, help="SSH username for VPS.")
    parser.add_argument("--image-url", required=True, help="Full URL of the Docker image to deploy.")
    parser.add_argument("--image-name", required=True, help="Base name for the Docker container.")
    parser.add_argument("--container-port", required=True, help="Internal port the container listens on.")
    parser.add_argument("--domain", required=True, help="Public domain name for Nginx.")
    # Secrets / Content will be read from environment variables
    args = parser.parse_args()

    # Read secrets/content from environment variables
    ssh_key_content = os.environ.get("SECRET_VPS_SSH_PRIVATE_KEY")
    ssl_cert_content = os.environ.get("SECRET_SSL_CERT")
    ssl_key_content = os.environ.get("SECRET_SSL_KEY")
    nginx_conf_b64 = os.environ.get("VAR_NGINX_CONF_B64") # Naming matches action env

    # Validate secrets exist
    if not all([ssh_key_content, ssl_cert_content, ssl_key_content, nginx_conf_b64]):
        log.critical("Missing one or more required secret environment variables (SSH Key, SSL Cert, SSL Key, Nginx B64).")
        sys.exit(1)

    temp_key_path = None
    exit_code = 0
    try:
        # Prepare SSH key file
        ssh_key_content_decoded = decode_if_base64(ssh_key_content) # Decode key if needed
        temp_key_path = write_temp_key_file(ssh_key_content_decoded)

        # Establish SSH connection
        log.info(f"Connecting to {args.user}@{args.host}...")
        connect_kwargs = {"key_filename": temp_key_path}
        # Add passphrase if your key is protected (read from env var or prompt securely if needed)
        # key_passphrase = os.environ.get("SSH_KEY_PASSPHRASE")
        # if key_passphrase:
        #     connect_kwargs["passphrase"] = key_passphrase

        connection = Connection(host=args.host, user=args.user, connect_kwargs=connect_kwargs)
        connection.open() # Explicitly open connection
        log.info("SSH connection established.")

        # Run deployment steps
        ensure_directories(connection)
        deploy_ssl_files(connection, args.domain, ssl_cert_content, ssl_key_content)
        deploy_nginx_config(connection, args.domain, nginx_conf_b64)
        deploy_docker_container(connection, args.image_url, args.image_name, args.container_port)
        validate_and_reload_nginx(connection)
        cleanup_docker_images(connection)

        log.info(f"[SUCCESS] Python Deployment Script Completed Successfully.")
        log.info(f"Application should be accessible at https://{args.domain}")

    except Exception as e:
        log.critical(f"Deployment failed: {e}", exc_info=True) # Log full traceback
        exit_code = 1
    finally:
        # Clean up temporary SSH key file
        if temp_key_path and os.path.exists(temp_key_path):
            log.debug(f"Removing temporary SSH key file: {temp_key_path}")
            try:
                os.remove(temp_key_path)
            except OSError as e:
                 log.warning(f"Could not remove temporary key file {temp_key_path}: {e}")
        # Close SSH connection if open
        if 'connection' in locals() and connection.is_connected:
            connection.close()
            log.debug("SSH connection closed.")

        duration = time.time() - start_time
        log.info(f"--- Python VPS Deployment Script Finished --- (Duration: {duration:.2f}s, Exit Code: {exit_code})")
        sys.exit(exit_code)

if __name__ == "__main__":
    # Add import for regex used in helper function
    import re
    main()