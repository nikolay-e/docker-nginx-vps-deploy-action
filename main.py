#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import time
from typing import Optional, Dict

# Local imports
from ssh_runner import SSHRunner # Assuming ssh_runner.py is in the same directory
from deployer import VpsDeployer # Assuming deployer.py is in the same directory

# --- Logging Setup --- (Copied from original deploy_vps.py)
SUCCESS_LEVEL_NUM = 25
logging.addLevelName(SUCCESS_LEVEL_NUM, "SUCCESS")
def success(self, message, *args, **kws):
    if self.isEnabledFor(SUCCESS_LEVEL_NUM):
        self._log(SUCCESS_LEVEL_NUM, message, args, **kws)
logging.Logger.success = success

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)-7s] [%(module)-10s] %(message)s', # Added module name
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger(__name__)
# if os.environ.get('ACTIONS_STEP_DEBUG') == 'true':
#     logging.getLogger().setLevel(logging.DEBUG) # Set root logger level

# --- Main Execution Logic ---
def main():
    start_time = time.time()
    log.info("--- Python Deployment Script Started ---")

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

    log.info("Deployment Settings:")
    log.info(f"  Host: {args.user}@{args.host}")
    log.info(f"  Image URL: {args.image_url}")
    # ... log other args similarly ...
    log.info(f"  Skip Nginx: {args.nginx_skip}")
    log.info(f"  Skip SSL: {args.ssl_skip}")

    # Read secrets from environment
    secrets = {
        "SECRET_VPS_SSH_PRIVATE_KEY": os.environ.get("SECRET_VPS_SSH_PRIVATE_KEY"),
        "SECRET_SSL_CERT": os.environ.get("SECRET_SSL_CERT"),
        "SECRET_SSL_KEY": os.environ.get("SECRET_SSL_KEY"),
        "VAR_NGINX_CONF_B64": os.environ.get("VAR_NGINX_CONF_B64"),
    }

    runner: Optional[SSHRunner] = None
    exit_code = 0
    try:
        # 1. Initialize SSH Runner (handles key and connection)
        runner = SSHRunner(
            host=args.host,
            user=args.user,
            ssh_key_secret=secrets.get("SECRET_VPS_SSH_PRIVATE_KEY")
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