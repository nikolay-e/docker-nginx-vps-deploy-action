#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import time
from typing import Optional, Dict

# Local imports
from ssh_runner import SSHRunner
from deployer import VpsDeployer
from utils import mask_secrets

# --- Custom Logging Filter ---
class SecretFilter(logging.Filter):
    """Filter to remove secrets from log messages"""
    
    def __init__(self, secrets):
        super().__init__()
        self.secrets = secrets
        
    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = mask_secrets(record.msg, self.secrets)
        
        if hasattr(record, 'args'):
            # Handle string formatting arguments
            args = list(record.args)
            for i, arg in enumerate(args):
                if isinstance(arg, str):
                    args[i] = mask_secrets(arg, self.secrets)
            record.args = tuple(args)
        return True

# --- Logging Setup ---
def setup_logging(secrets):
    """Set up logging with secret filtering"""
    SUCCESS_LEVEL_NUM = 25
    logging.addLevelName(SUCCESS_LEVEL_NUM, "SUCCESS")
    
    def success(self, message, *args, **kws):
        if self.isEnabledFor(SUCCESS_LEVEL_NUM):
            self._log(SUCCESS_LEVEL_NUM, message, args, **kws)
    
    logging.Logger.success = success
    
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)-7s] [%(module)-10s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Add our secret filter to all handlers
    root_logger = logging.getLogger()
    secret_filter = SecretFilter(secrets)
    for handler in root_logger.handlers:
        handler.addFilter(secret_filter)
    
    return logging.getLogger(__name__)

# --- Main Execution Logic ---
def main():
    start_time = time.time()
    
    parser = argparse.ArgumentParser(description="Deploy Docker container to VPS with optional Nginx setup.")
    # Add arguments matching action inputs
    parser.add_argument("--host", required=True, help="VPS hostname or IP address.")
    parser.add_argument("--user", required=True, help="SSH username for VPS.")
    parser.add_argument("--image-url", required=True, help="Full URL of the Docker image to deploy.")
    parser.add_argument("--image-name", required=True, help="Base name for the Docker image/container.")
    parser.add_argument("--container-port", required=True, help="Host port (on 127.0.0.1) to map to container's internal port.")
    parser.add_argument("--container-internal-port", required=True, help="Internal port the container listens on.")
    parser.add_argument("--domain", required=True, help="Public domain name for Nginx/SSL.")
    parser.add_argument("--nginx-skip", type=lambda x: (str(x).lower() == 'true'), default=False, help="Skip Nginx setup if true.")
    parser.add_argument("--ssl-skip", type=lambda x: (str(x).lower() == 'true'), default=False, help="Skip SSL setup if true.")
    parser.add_argument("--docker-prune-filter", required=True, help="Filter for 'docker image prune -af'.")
    args = parser.parse_args()

    # Read secrets from environment - do this before setting up logging
    secrets = {
        "SECRET_VPS_SSH_PRIVATE_KEY": os.environ.get("SECRET_VPS_SSH_PRIVATE_KEY"),
        "SECRET_SSL_CERT": os.environ.get("SECRET_SSL_CERT"),
        "SECRET_SSL_KEY": os.environ.get("SECRET_SSL_KEY"),
        "VAR_NGINX_CONF_B64": os.environ.get("VAR_NGINX_CONF_B64"),
    }
    
    # Set up logging with secret filtering
    log = setup_logging(secrets)
    
    log.info("--- Python Deployment Script Started ---")
    log.info("Deployment Settings:")
    log.info(f"  Host: {args.user}@{args.host}")
    log.info(f"  Image URL: {args.image_url}")
    log.info(f"  Image Name: {args.image_name}")
    log.info(f"  Container Port: {args.container_port}")
    log.info(f"  Container Internal Port: {args.container_internal_port}")
    log.info(f"  Domain: {args.domain}")
    log.info(f"  Skip Nginx: {args.nginx_skip}")
    log.info(f"  Skip SSL: {args.ssl_skip}")
    log.info(f"  Docker prune filter: {args.docker_prune_filter}")

    runner: Optional[SSHRunner] = None
    exit_code = 0
    try:
        # 1. Initialize SSH Runner (handles key and connection)
        runner = SSHRunner(
            host=args.host,
            user=args.user,
            ssh_key_secret=secrets.get("SECRET_VPS_SSH_PRIVATE_KEY"),
            secrets_dict=secrets  # Pass secrets for masking
        )

        # 2. Initialize Deployer with the runner
        deployer = VpsDeployer(args, secrets, runner)

        # 3. Run the deployment workflow
        deployer.run()

    except (ValueError, IOError, RuntimeError) as e:
        # Catch specific errors raised during setup or deployment
        log.critical(f"DEPLOYMENT FAILED: {e.__class__.__name__}: {e}")
        exit_code = 1
    except Exception as e:
        # Catch any unexpected errors
        log.critical("An unexpected critical error occurred.", exc_info=True)
        exit_code = 1
    finally:
        if runner:
            runner.close() # Ensure SSH connection and key file are cleaned up

        duration = time.time() - start_time
        log.info(f"--- Python Deployment Script Finished --- (Duration: {duration:.2f}s, Exit Code: {exit_code})")
        sys.exit(exit_code)

if __name__ == "__main__":
    main()