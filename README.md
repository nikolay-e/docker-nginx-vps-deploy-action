# Docker Build, Push, and Deploy to VPS Action

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) <!-- Add a LICENSE file -->

This GitHub Action automates the process of:

1.  Building a Docker image from your repository.
2.  Pushing the image to a specified Docker registry (e.g., Docker Hub).
3.  Connecting to a Virtual Private Server (VPS) via SSH.
4.  Deploying the new Docker image as a container on the VPS.
5.  Configuring Nginx on the VPS as a reverse proxy for your application.
6.  Handling SSL certificates and keys (provided as secrets).

## Features

*   Builds and pushes Docker images using `docker/build-push-action`.
*   Tags images with the Git commit SHA and optionally `latest` (for main/master branch).
*   Uses `appleboy/ssh-action` for secure deployment to the VPS.
*   Generates and deploys an Nginx configuration for reverse proxying.
*   Supports SSL termination via provided certificate and key secrets.
*   **Handles Secrets (SSH Key, SSL Cert, SSL Key) provided as raw strings OR Base64 encoded strings.**
*   Cleans up old Docker images on the VPS.
*   Provides outputs: `image-tag`, `image-url`, `deployment-url`.

## Usage

### Prerequisites

1.  **Docker Registry Account**: You need an account on a Docker registry (like Docker Hub).
2.  **VPS Setup**:
    *   A Linux VPS with SSH access configured (key-based authentication recommended).
    *   **Docker installed** on the VPS.
    *   **Nginx installed** on the VPS.
    *   The SSH user (`vps-user`) must have `sudo` privileges (or permissions to manage Docker, Nginx configs, and systemd services).
    *   Firewall configured to allow HTTP (80) and HTTPS (443) traffic.
3.  **SSL Certificate and Key**: You need your SSL certificate and private key files.
4.  **GitHub Repository Secrets**: Add the following secrets in your GitHub repository settings (`Settings > Secrets and variables > Actions > New repository secret`):
    *   `DOCKER_REGISTRY_TOKEN`: Your Docker registry access token or password.
    *   `VPS_SSH_PRIVATE_KEY`: The private SSH key content for accessing your VPS. **Can be the raw key string (including `-----BEGIN...` lines) or a Base64 encoded version of the key file.**
    *   `SSL_CERT`: The full SSL certificate content (including `-----BEGIN CERTIFICATE...` lines). **Can be raw or Base64 encoded.**
    *   `SSL_KEY`: The SSL private key content (including `-----BEGIN PRIVATE KEY...` lines). **Can be raw or Base64 encoded.**

### Example Workflow

```yaml
name: Build and Deploy Application

on:
  push:
    branches:
      - main # Deploy only when merging to main

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      # 1. Checkout code is necessary for the Docker build context
      - name: Checkout code
        uses: actions/checkout@v4

      # 2. Run the deployment action
      - name: Build and Deploy to VPS
        id: deploy # Give the step an ID to reference outputs
        uses: your-username/docker-vps-deploy-action@latest # Replace with your action repo and version
        with:
          # Docker build inputs
          image-name: 'my-cool-app' # Your desired image name
          docker-registry-username: ${{ secrets.DOCKER_USERNAME }} # Use secret for username

          # Deployment inputs
          vps-host: ${{ secrets.VPS_HOST }} # Use secret for host IP/domain
          vps-user: 'deploy-user' # Your SSH username on the VPS
          container-port: 8080 # The port your app listens on INSIDE the container
          domain: 'app.yourdomain.com' # The domain Nginx will serve

          # Optional docker build inputs:
          # docker-context: './backend' # If Dockerfile is not in root
          # docker-file: './backend/Dockerfile.prod'

        env: # Pass secrets to the Action via environment variables
          DOCKER_REGISTRY_TOKEN: ${{ secrets.DOCKER_REGISTRY_TOKEN }}
          VPS_SSH_PRIVATE_KEY: ${{ secrets.VPS_SSH_PRIVATE_KEY }}
          SSL_CERT: ${{ secrets.SSL_CERT }}
          SSL_KEY: ${{ secrets.SSL_KEY }}

      # 3. Example: Print deployment URL
      - name: Print Deployment URL
        run: echo "Application deployed to: ${{ steps.deploy.outputs.deployment-url }}"