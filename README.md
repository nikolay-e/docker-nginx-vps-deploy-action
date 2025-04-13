# Docker Build, Push, and Deploy to VPS Action

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/nikolay-e/docker-nginx-vps-deploy-action)](https://github.com/nikolay-e/docker-nginx-vps-deploy-action/releases)
[![GitHub Action Status](https://github.com/nikolay-e/docker-nginx-vps-deploy-action/actions/workflows/main.yml/badge.svg)](https://github.com/nikolay-e/docker-nginx-vps-deploy-action/actions/workflows/main.yml)

This GitHub Action automates the process of:
1.  Building a Docker image from your repository.
2.  Pushing the image to a specified Docker registry (e.g., Docker Hub).
3.  Connecting to a Virtual Private Server (VPS) via SSH using key-based authentication.
4.  Deploying the new Docker image as a container on the VPS.
5.  Optionally: Configuring Nginx on the VPS as a reverse proxy for your application using a template.
6.  Optionally: Handling SSL certificates and keys (provided as secrets) for HTTPS.
7.  Cleaning up old Docker images on the VPS.

## Features

* Builds and pushes Docker images using `docker/build-push-action`.
* Tags images with the short Git commit SHA and optionally `latest` (for main/master branch).
* Uses Python with `Fabric` for robust SSH command execution and file transfer.
* Generates and deploys an Nginx configuration from an internal template for reverse proxying (optional).
* Supports SSL termination via provided certificate and key secrets (optional).
* **Handles Secrets (SSH Key, SSL Cert, SSL Key) provided as raw PEM strings OR Base64 encoded strings.** Detects encoding automatically.
* Cleans up old Docker images on the VPS using a configurable filter.
* Provides outputs: `image-tag`, `image-url`, `deployment-url`.
* Configurable skipping of Nginx and SSL steps (`nginx-skip`, `ssl-skip`).
* Configurable internal container port mapping (`container-internal-port`).
* Improved error handling and logging within the deployment script.

## Prerequisites

1.  **Docker Registry Account**: Account on Docker Hub or another container registry.
2.  **VPS Setup**:
    * A Linux VPS (e.g., Ubuntu, Debian, CentOS tested).
    * **SSH Server configured** for key-based authentication. Direct root login is highly discouraged; use a dedicated deployment user.
    * **Deployment User (`vps-user`)**: Must have **passwordless `sudo` privileges**. This is crucial for managing Docker (if not rootless), Nginx configs/service, creating directories, and setting file permissions. Test this manually: `ssh <vps-user>@<vps-host> sudo whoami` should return `root` without asking for a password.
    * **Docker Installed**: The Docker engine must be installed and running. See [official Docker installation docs](https://docs.docker.com/engine/install/). The deployment user should ideally be in the `docker` group or Docker should run in rootless mode.
    * **Nginx Installed** (if `nginx-skip: false`): Nginx web server must be installed and running. See [official Nginx installation docs](https://nginx.org/en/docs/install.html).
    * **Required Commands**: Ensure essential commands (`docker`, `systemctl`, `mkdir`, `chmod`, `chown`, `mv`, `rm`, `ln`, `tee`, `command`, `whoami`, and `nginx` if used) are available in the system `$PATH` for the deployment user (including via `sudo`).
    * **Firewall**: Configured to allow incoming traffic on port 80 (HTTP) and 443 (HTTPS) if using Nginx/SSL. Also ensure SSH port (usually 22) is open.
3.  **SSL Certificate and Key** (if `ssl-skip: false`):
    * Your SSL certificate file (PEM format, including intermediate certificates - full chain recommended).
    * Your SSL private key file (PEM format). **Must not be password protected**.
4.  **DNS**: The `domain` input you provide must have its DNS A (and possibly AAAA) record pointing to your VPS's public IP address. Allow time for DNS propagation.
5.  **GitHub Repository Secrets**: Add the following secrets in your repository settings (`Settings > Secrets and variables > Actions > New repository secret`):
    * `DOCKER_REGISTRY_TOKEN`: Your Docker registry access token or password. For Docker Hub, create an Access Token.
    * `VPS_SSH_PRIVATE_KEY`: The **content** of the private SSH key file for accessing your VPS. **Do not use a key protected by a passphrase.**
        * Can be the **raw PEM string** (copy the entire content including `-----BEGIN...` and `-----END...` lines).
        * Can be **Base64 encoded** content of the key file. (e.g., run `base64 -w 0 < path/to/your/key.pem` on Linux/macOS and copy the output).
    * `SSL_CERT` (if `ssl-skip: false`): The **content** of your SSL certificate file (PEM, full chain recommended). Raw or Base64 encoded.
    * `SSL_KEY` (if `ssl-skip: false`): The **content** of your SSL private key file (PEM). Raw or Base64 encoded. **Must not be password protected.**

## Inputs

| Name                    | Description                                                                                           | Required | Default      |
| :---------------------- | :---------------------------------------------------------------------------------------------------- | :------- | :----------- |
| `image-name`            | Base name for the Docker image (e.g., 'my-web-app').                                                  | `true`   |              |
| `docker-registry-user`| Username for the Docker registry.                                                                     | `true`   |              |
| `docker-context`        | Path to the Docker build context directory.                                                           | `false`  | `.`          |
| `docker-file`           | Path to the Dockerfile, relative to `docker-context`.                                                 | `false`  | `Dockerfile` |
| `vps-host`              | Hostname or IP address of the target VPS.                                                             | `true`   |              |
| `vps-user`              | Username for SSH login (must have passwordless `sudo`).                                               | `true`   |              |
| `container-port`        | The host port (on `127.0.0.1`) Nginx proxies to.                                                        | `true`   |              |
| `container-internal-port`| The port the app listens on *inside* the container.                                                   | `false`  | `'80'`       |
| `domain`                | The public domain name for Nginx/SSL config.                                                          | `true`   |              |
| `nginx-skip`            | Set to `'true'` to skip Nginx configuration steps.                                                    | `false`  | `'false'`    |
| `ssl-skip`              | Set to `'true'` to skip SSL certificate deployment (Nginx will use HTTP only if `nginx-skip: false`). | `false`  | `'false'`    |
| `docker-prune-filter`   | Filter for `docker image prune -af`.                                                                  | `false`  | `'until=1h'` |

*Secrets (`DOCKER_REGISTRY_TOKEN`, `VPS_SSH_PRIVATE_KEY`, `SSL_CERT`, `SSL_KEY`) must be passed via the `env` block in your workflow.*

## Outputs

| Name             | Description                                                                  |
| :--------------- | :--------------------------------------------------------------------------- |
| `image-tag`      | The short git SHA tag used for the built image (e.g., 'a1b2c3d').            |
| `image-url`      | The full URL of the pushed image, including the tag.                         |
| `deployment-url` | The final URL (HTTPS or HTTP) where the application is expected to be available. |

## Usage Example

```yaml
name: Build and Deploy Application

on:
  push:
    branches:
      - main # Deploy only when pushing to the main branch

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      # 1. Checkout code (needed for Docker build context)
      - name: Checkout code
        uses: actions/checkout@v4

      # 2. Run the deployment action
      - name: Build and Deploy to VPS
        id: deploy # Give the step an ID to reference outputs
        # Use a specific version tag or major version tag like @v1 for stability
        uses: nikolay-e/docker-nginx-vps-deploy-action@v1.0.0 # Or @v1
        with:
          # --- Required Inputs ---
          image-name: 'my-cool-app'
          docker-registry-username: ${{ secrets.DOCKER_USERNAME }} # Use a secret or your username
          vps-host: ${{ secrets.VPS_HOST }} # Use a secret
          vps-user: 'deployer' # Your SSH username on the VPS
          container-port: '8080' # Port Nginx proxies to (on 127.0.0.1)
          domain: 'app.yourdomain.com'

          # --- Optional Inputs ---
          # container-internal-port: '3000' # If your app runs on port 3000 inside Docker
          # docker-context: './backend'
          # docker-file: './backend/Dockerfile.prod'
          # nginx-skip: 'true' # Skip Nginx setup entirely
          # ssl-skip: 'true' # Use HTTP instead of HTTPS with Nginx
          # docker-prune-filter: 'label=stage=production'

        env: # Pass secrets securely via environment variables
          DOCKER_REGISTRY_TOKEN: ${{ secrets.DOCKER_REGISTRY_TOKEN }}
          VPS_SSH_PRIVATE_KEY: ${{ secrets.VPS_SSH_PRIVATE_KEY }}
          # Only needed if ssl-skip is 'false' (default)
          SSL_CERT: ${{ secrets.SSL_CERT }}
          SSL_KEY: ${{ secrets.SSL_KEY }}

      # 3. Example: Use the deployment output
      - name: Print Deployment URL
        run: echo "Application deployed! Access it at: ${{ steps.deploy.outputs.deployment-url }}"
