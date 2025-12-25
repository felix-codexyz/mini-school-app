# Jenkins Pipeline for Multi-Environment Docker Deployment to AWS

## Overview

This Jenkins pipeline automates the deployment of a Dockerized React application to Amazon Elastic Container Registry (ECR) and Amazon EC2 instances across three AWS environments (Dev, Staging, Prod) managed by AWS Organizations. The pipeline:

- Assumes an IAM role in the target AWS account using STS.
- Validates or creates an ECR repository with minimal API calls.
- Builds and pushes a Docker image with environment-specific tags.
- Deploys the image to a pre-existing EC2 instance via secure SSH with `known_hosts`.
- Validates inputs and AWS resources to ensure reliable execution.

The pipeline is parameterized for flexibility, allowing users to specify the target environment, AWS account details, EC2 instance information, and host port

## Prerequisites

### Jenkins

- **Jenkins Version**: 2.426.3 or later (LTS recommended).
- **Plugins**:
  - **Pipeline Plugin**: For declarative pipeline support.
  - **Credentials Binding Plugin**: For secure AWS and SSH credential handling.
  - **AWS Credentials Plugin**: For AWS credential integration.
  - **Pipeline Utility Steps Plugin**: For JSON parsing (`readJSON`).
  - **Email Extension Plugin** (optional): For email notifications (planned extension).
  - **Mailer Plugin** (optional): Dependency for email notifications.
- **Jenkins Node**:
  - Label: `docker-node`.
  - Must have:
    - Docker (for building and pushing images).
    - AWS CLI v2 (for AWS interactions).
    - SSH client (`ssh`, `scp`, `ssh-keyscan`, `timeout` for EC2 access).
    - Linux-based (e.g., Ubuntu) with `bash` for script execution.

### AWS

- **AWS Accounts**:
  - A Management Account with an IAM user for assuming roles.
  - Target accounts (Dev, Staging, Prod) managed by AWS Organizations.
- **IAM Setup**:
  - **Management Account IAM User**:
    - Permissions: `sts:AssumeRole` for target account roles.
    - Credentials: Access Key ID and Secret Access Key (stored in Jenkins).
  - **Target Account Roles**:
    - Role Name: `CrossAccountRole` (or as specified).
    - Trust Policy: Allows the Management Account IAM user to assume the role.
    - Permissions:
      - ECR: `ecr:CreateRepository`, `ecr:DescribeRepositories`, `ecr:GetAuthorizationToken`, `ecr:PutImage`, etc.
      - EC2: `ec2:DescribeInstances` for validation.
  - **ECR**:
    - Repositories created dynamically (e.g., `my-app-dev`, `my-app-staging`, `my-app-prod`).
  - **EC2**:
    - Pre-existing instances in each environment.
    - Instance Profile: Grants ECR pull permissions (e.g., `AmazonEC2ContainerRegistryReadOnly`).
    - Docker: Installed and configured (user `ubuntu` must have Docker access without `sudo`).
    - SSH: Port 22 open, accessible from the Jenkins node’s IP.
    - Key Pair: Matching private key stored in Jenkins.(`SSM Recommended`)
- **Region**: `us-east-1` (configurable via parameters).

### Application

- **Source Code**:
  - A React application with:
    - `Dockerfile`: Multi-stage build (Node for building, Nginx for serving).
    - `nginx.conf`: Custom Nginx configuration for the React app.
    - `package.json`, `package-lock.json`: Node dependencies.
    - Application code in the repository root.
- **Dockerfile**: Builds a React app and serves it via Nginx on port 80.

## AWS Configuration

1. **IAM User (Management Account)**:
   - Create an IAM user on the console or through CLI with the policy below.
   - Attach a policy allowing `sts:AssumeRole`:
     ```json
     {
         "Version": "2012-10-17",
         "Statement": [
             {
                 "Effect": "Allow",
                 "Action": "sts:AssumeRole",
                 "Resource": "arn:aws:iam::*:role/CrossAccountRole"
             }
         ]
     }
     ```
   - Generate and save the Access Key ID and Secret Access Key.

2. **IAM Role (Target Accounts)**:
   - In each target account, create a role (e.g., `CrossAccountRole`).
   - Trust Policy:
     ```json
     {
         "Version": "2012-10-17",
         "Statement": [
             {
                 "Effect": "Allow",
                 "Principal": {
                     "AWS": "arn:aws:iam::<management-account-id>:user/<iam-user-name>"
                 },
                 "Action": "sts:AssumeRole"
             }
         ]
     }
     ```
   - Attach policies for ECR and EC2:
     ```json
     {
         "Version": "2012-10-17",
         "Statement": [
             {
                 "Effect": "Allow",
                 "Action": [
                     "ecr:DescribeRepositories",
                     "ecr:CreateRepository",
                     "ecr:GetAuthorizationToken",
                     "ecr:BatchCheckLayerAvailability",
                     "ecr:PutImage",
                     "ecr:InitiateLayerUpload",
                     "ecr:UploadLayerPart",
                     "ecr:CompleteLayerUpload",
                     "ec2:DescribeInstances"
                 ],
                 "Resource": "*"
             }
         ]
     }
     ```

3. **EC2 Instances**:
   - Launch instances with:
     - AMI: Ubuntu-based (e.g., Ubuntu 24.04).
     - Instance Profile: Attached with ECR Read-Only permissions.
     - Security Group: Allow inbound SSH (port 22) from Jenkins node IP and HTTP (port 80).
     - Key Pair: Same key pair across environments.
   - Install Docker:
   - Verify `ubuntu` user runs Docker without `sudo`: `docker ps`.

4. **ECR**:
   - No pre-existing repositories required; pipeline creates them dynamically.

## Jenkins Configuration

1. **Credentials**:
   - Go to **Manage Jenkins > Credentials > System > Global credentials**.
   - Add:
     - **AWS Credentials**:
       - Kind: AWS Credentials.
       - ID: `sts-user`.
       - Access Key ID: From Management Account IAM user.
       - Secret Access Key: From Management Account IAM user.
     - **SSH Credentials**:
       - Kind: SSH Username with private key.
       - ID: `ec2-key`.
       - Username: `ubuntu`.
       - Private Key: Paste the EC2 instance’s private key.
     - **Gmail SMTP Credentials** (optional, for notifications):
       - Kind: Username with Password.
       - ID: `gmail-smtp`.
       - Username: Gmail address.
       - Password: Gmail App Password.

2. **Node Configuration**:
   - Ensure a node labeled `docker-node` has:
     - Docker: `docker --version`.
     - AWS CLI: `aws --version`.
     - SSH tools: `ssh`, `scp`, `ssh-keyscan`, `timeout`.

3. **Pipeline Setup**:
   - Create a Pipeline job.
   - Reference the `Jenkinsfile` from your repository or paste it directly.
   - Ensure the repository includes `Dockerfile`, `nginx.conf`, and app code.

## Pipeline Structure

The pipeline is declarative, optimized for efficiency and security, with the following stages and parameters.

### Parameters

- **ENVIRONMENT**: `DEV`, `STAGING`, or `PROD`.
- **AWS_ACCOUNT_ID**: 12-digit target account ID (e.g., `12345678910`).
- **ROLE_NAME**: IAM role (default: `CrossAccountRole`).
- **AWS_REGION**: AWS region (default: `us-east-1`).
- **ECR_REPO_NAME**: Base repository name (default: `my-app`).
- **EC2_INSTANCE_ID**: EC2 instance ID (e.g., `i-0fa1266b4dc575ay7`).
- **EC2_SSH_USER**: SSH user (default: `ubuntu`).
- **HOST_PORT**: Host port for Docker container (default: `80`).

### Stages

1. **Validate Input**:
   - Validates parameters (e.g., `AWS_ACCOUNT_ID` is 12 digits, `HOST_PORT` is 1–65535).
   - Fails with descriptive error if invalid.

2. **Assume Role**:
   - Assumes `CrossAccountRole` in the target account using `sts-user` credentials.
   - Stores temporary credentials as environment variables.

3. **Validate/Create ECR Repository**:
   - Checks for repository (e.g., `my-app-dev`) with a single `aws ecr describe-repositories` call.
   - Creates it if missing, avoiding redundant validations.
   - Sets `ECR_REPO_URL` for image tagging.

4. **Build and Push Docker Image**:
   - Builds the Docker image (e.g., `my-app:dev-<build-id>`).
   - Authenticates to ECR and pushes the image to `ECR_REPO_URL`.

5. **Validate EC2 Instance**:
   - Uses minimal `aws ec2 describe-instances` calls to verify instance state (`running`) and retrieve IP.
   - Fails if instance is not found, stopped, or lacks an IP.

6. **Deploy to EC2**:
   - Generates `known_hosts` using `ssh-keyscan` for secure SSH.
   - Creates and executes `deploy.sh` on EC2 to:
     - Pull the image from ECR.
     - Clean up old images (except the new one).
     - Stop/remove existing container.
     - Run the new container on `HOST_PORT:80`.
   - Cleans up SSH files securely.

### Post-Conditions

- **Failure**: Logs a failure message (extendable with email notifications).
- **Always**: Clears temporary AWS credentials.

## Usage

1. **Trigger the Pipeline**:
   - In Jenkins, click **Build with Parameters**.
   - Enter:
     - `ENVIRONMENT`: `DEV`, `STAGING`, or `PROD`.
     - `AWS_ACCOUNT_ID`: e.g., `12345678910`.
     - `ROLE_NAME`: `CrossAccountRole`.
     - `AWS_REGION`: `us-east-1`.
     - `ECR_REPO_NAME`: `my-app`.
     - `EC2_INSTANCE_ID`: e.g., `i-0fa1266b4dc575ay7`.
     - `EC2_SSH_USER`: `ubuntu`.
     - `HOST_PORT`: `80`.
   - Click **Build**.

2. **Monitor Execution**:
   - Check console output for stage progress.
   - Review errors for specific failures.

3. **Verify Deployment**:
   - Access `http://<ec2-ip>:<HOST_PORT>` (e.g., `http://18.209.210.162:80`).
   - SSH to EC2: `docker ps` to confirm the container.
   - Check `docker images` for old image cleanup.

## Security Considerations

- **Credentials**:
  - Store AWS (`sts-user`), SSH (`ec2-key`), and Gmail (`gmail-smtp`) credentials in Jenkins’ credentials store.
  - Restrict credential access to authorized users.
- **IAM Roles**:
  - Use least privilege for `CrossAccountRole` and Management Account IAM user.
- **EC2 Security**:
  - Limit SSH (port 22) to Jenkins node IP in the security group (`sg-0cf4773c4639d9543`).
  - Use `known_hosts` via `ssh-keyscan` for host verification.
- **ECR**:
  - Enable encryption/scanning for repositories (configurable in `aws ecr create-repository`).
- **Pipeline**:
  - Temporary credentials cleared in `post` block.
  - Secure SSH key handling with `chmod 600` and cleanup.

## Pipeline Command Reference

This section explains each command used in the pipeline, including shell commands (AWS CLI, Docker, SSH) and Jenkins/Groovy commands, along with their purpose and usage.

### Jenkins/Groovy Commands

1. **`pipeline { ... }`**:
   - **Purpose**: Defines a declarative Jenkins pipeline, structuring the build process into stages and steps.
   - **Usage**: Organizes the pipeline with `agent`, `parameters`, `stages`, and `post` blocks.
   - **Example**: `pipeline { agent { label 'docker-node' } ... }` runs the pipeline on a node labeled `docker-node`.

2. **`parameters { ... }`**:
   - **Purpose**: Defines user-input parameters for the pipeline, prompting users when the build is triggered.
   - **Usage**: Specifies choices (e.g., `ENVIRONMENT`) or strings (e.g., `AWS_ACCOUNT_ID`) with defaults and descriptions.
   - **Example**: `choice(name: 'ENVIRONMENT', choices: ['DEV', 'STAGING', 'PROD'])` creates a dropdown for environment selection.

3. **`agent { label 'docker-node' }`**:
   - **Purpose**: Specifies the Jenkins node where the pipeline runs.
   - **Usage**: Ensures the pipeline executes on a node with Docker and AWS CLI installed.
   - **Example**: Runs on a node labeled `docker-node`.

4. **`script { ... }`**:
   - **Purpose**: Allows scripted pipeline syntax within a declarative pipeline for complex logic.
   - **Usage**: Used for conditional checks, variable assignments, and JSON parsing.
   - **Example**: `script { if (!params.ENVIRONMENT) { error "Invalid ENVIRONMENT" } }` validates inputs.

5. **`error "message"`**:
   - **Purpose**: Fails the pipeline and displays a custom error message.
   - **Usage**: Stops execution when validation fails or resources are inaccessible.
   - **Example**: `error "Invalid AWS_ACCOUNT_ID"` halts the pipeline for an invalid account ID.

6. **`withCredentials([ ... ]) { ... }`**:
   - **Purpose**: Securely binds credentials from Jenkins’ credentials store to variables or files.
   - **Usage**: Used for AWS credentials (`management-account-iam-user`) and SSH key (`ec2-key`).
   - **Example**:
     ```groovy
     withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'management-account-iam-user', ...]]) { ... }
     ```
     Binds AWS access key and secret key to `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

     ```groovy
     withCredentials([sshUserPrivateKey(credentialsId: 'ec2-key', keyFileVariable: 'SSH_KEY', usernameVariable: 'SSH_USERNAME')]) { ... }
     ```
     Writes the SSH private key to a temporary file (`SSH_KEY`) for `scp` and `ssh`.

7. **`sh "command"`**:
   - **Purpose**: Executes a shell command on the Jenkins node and captures output or status.
   - **Usage**: Runs AWS CLI, Docker, and SSH commands.
   - **Example**: `sh "docker build -t my-app:dev-123 ."` builds a Docker image.
   - **Options**:
     - `returnStdout: true`: Captures command output (e.g., for `aws sts assume-role`).
     - `returnStatus: true`: Captures exit code (e.g., for `aws ecr describe-repositories`).

8. **`readJSON text: output`**:
   - **Purpose**: Parses JSON output into a Groovy object for accessing fields.
   - **Usage**: Extracts temporary credentials from `aws sts assume-role` output.
   - **Example**: `def stsJson = readJSON text: stsOutput` parses STS JSON to access `Credentials.AccessKeyId`.

9. **`writeFile file: 'name', text: 'content'`**:
   - **Purpose**: Writes content to a file on the Jenkins node’s workspace.
   - **Usage**: Creates the `deploy.sh` script for EC2 deployment.
   - **Example**: `writeFile file: 'deploy.sh', text: "#!/bin/bash\nset -e\n..."` writes the deployment script.

10. **`echo "message"`**:
    - **Purpose**: Prints a message to the Jenkins console for logging.
    - **Usage**: Logs status updates (e.g., repository creation).
    - **Example**: `echo "ECR repository my-app-dev already exists."` informs the user of repository status.

### Shell Commands (AWS CLI)

1. **`aws sts assume-role --role-arn <arn> --role-session-name <name> --output json`**:
   - **Purpose**: Assumes an IAM role in the target account, returning temporary credentials.
   - **Usage**: Authenticates to the target account (e.g., Dev) using the Management Account IAM user.
   - **Example**: `aws sts assume-role --role-arn arn:aws:iam::392102158411:role/OrganizationAccountAccessRole --role-session-name JenkinsSession-123` generates credentials.

2. **`aws ecr describe-repositories --region <region> --repository-names <name> --output json`**:
   - **Purpose**: Checks if an ECR repository exists.
   - **Usage**: Validates the repository (e.g., `my-app-dev`) before pushing images.
   - **Example**: `aws ecr describe-repositories --region us-east-1 --repository-names my-app-dev` returns repository details or fails if not found.

3. **`aws ecr create-repository --region <region> --repository-name <name> --output json`**:
   - **Purpose**: Creates a new ECR repository if it doesn’t exist.
   - **Usage**: Sets up environment-specific repositories (e.g., `my-app-dev`).
   - **Example**: `aws ecr create-repository --region us-east-1 --repository-name my-app-dev` creates the repository.

4. **`aws ecr get-login-password --region <region>`**:
   - **Purpose**: Retrieves an authentication token for Docker to access ECR.
   - **Usage**: Authenticates Docker to push or pull images.
   - **Example**: `aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com` logs Docker into ECR.

5. **`aws ec2 describe-instances --region <region> --instance-ids <id> --query 'Reservations[0].Instances[0].State.Name' --output text`**:
   - **Purpose**: Checks the state of an EC2 instance (e.g., `running`, `stopped`).
   - **Usage**: Validates the EC2 instance exists and is running.
   - **Example**: `aws ec2 describe-instances --region us-east-1 --instance-ids i-0fa1266b4dc575aa7 --query 'Reservations[0].Instances[0].State.Name'` returns `running` or fails.

6. **`aws ec2 describe-instances --region <region> --instance-ids <id> --query 'Reservations[0].Instances[0].PublicIpAddress' --output text`**:
   - **Purpose**: Retrieves the public IP of the EC2 instance for SSH.
   - **Usage**: Gets the IP for connecting to the instance.
   - **Example**: Returns the public IP or empty if not available.

7. **`aws ec2 describe-instances --region <region> --instance-ids <id> --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text`**:
   - **Purpose**: Retrieves the private IP as a fallback if the public IP is unavailable.
   - **Usage**: Ensures an IP is available for SSH.
   - **Example**: Returns the private IP for VPC-internal access.

### Shell Commands (Docker)

1. **`docker build -t <name:tag> .`**:
   - **Purpose**: Builds a Docker image from the `Dockerfile` in the current directory.
   - **Usage**: Creates the React app image with a unique tag.
   - **Example**: `docker build -t my-app:dev-123 .` builds the image.

2. **`docker login --username AWS --password-stdin <ecr-url>`**:
   - **Purpose**: Authenticates Docker to the ECR registry.
   - **Usage**: Uses the token from `aws ecr get-login-password` to log in.
   - **Example**: `docker login --username AWS --password-stdin 12345678910.dkr.ecr.us-east-1.amazonaws.com` authenticates Docker.

3. **`docker tag <source:tag> <target:tag>`**:
   - **Purpose**: Tags a Docker image for pushing to ECR.
   - **Usage**: Assigns the ECR repository URL and tag to the image.
   - **Example**: `docker tag my-app:dev-123 12345678910.dkr.ecr.us-east-1.amazonaws.com/my-app-dev:dev-123` prepares the image for ECR.

4. **`docker push <image:tag>`**:
   - **Purpose**: Pushes the Docker image to the ECR repository.
   - **Usage**: Uploads the image to the specified repository.
   - **Example**: `docker push 12345678910.dkr.ecr.us-east-1.amazonaws.com/my-app-dev:dev-123` uploads the image.

5. **`docker pull <image:tag>`**:
   - **Purpose**: Pulls the Docker image from ECR to the EC2 instance.
   - **Usage**: Downloads the latest image for deployment.
   - **Example**: `docker pull 12345678910.dkr.ecr.us-east-1.amazonaws.com/my-app-dev:dev-123` retrieves the image.

6. **`docker stop <container>`**:
   - **Purpose**: Stops a running Docker container.
   - **Usage**: Stops the existing container (if any) before redeployment.
   - **Example**: `docker stop my-app-123 || true` stops the container, ignoring errors if it doesn’t exist.

7. **`docker rm <container>`**:
   - **Purpose**: Removes a stopped Docker container.
   - **Usage**: Cleans up the old container before running a new one.
   - **Example**: `docker rm my-app-123 || true` removes the container, ignoring errors.

8. **`docker run -d --name <name> -p 80:80 <image:tag>`**:
   - **Purpose**: Runs a new Docker container in detached mode.
   - **Usage**: Starts the React app container, mapping port 80.
   - **Example**: `docker run -d --name my-app-123 -p 80:80 12345678910.dkr.ecr.us-east-1.amazonaws.com/my-app-dev:dev-123` runs the container.

### Shell Commands (SSH and File Management)

1. **`mkdir -p ${WORKSPACE}/.ssh`**:
   - **Purpose**: Creates an `.ssh` directory in the Jenkins workspace to store the `known_hosts` file.
   - **Usage**: Ensures a secure location for SSH configuration files.
   - **Example**: `mkdir -p ${WORKSPACE}/.ssh` creates the directory if it doesn’t exist.

2. **`timeout 10s ssh-keyscan -t rsa,ecdsa,ed25519 -H <ip> >> ${WORKSPACE}/.ssh/known_hosts`**:
   - **Purpose**: Generates a `known_hosts` file with the EC2 instance’s host keys for secure SSH verification.
   - **Usage**: Runs `ssh-keyscan` with a 10-second timeout to fetch RSA, ECDSA, and ED25519 keys, appending them to `known_hosts`.
   - **Example**: `timeout 10s ssh-keyscan -t rsa,ecdsa,ed25519 -H 18.209.210.162 >> ${WORKSPACE}/.ssh/known_hosts` secures SSH connections.

3. **`chmod 600 $SSH_KEY`**:
   - **Purpose**: Sets secure permissions (read/write for owner only) on the SSH private key file.
   - **Usage**: Ensures the key file is secure before use with `scp` or `ssh`.
   - **Example**: `chmod 600 $SSH_KEY` secures the temporary key file.

4. **`scp -i $SSH_KEY -o UserKnownHostsFile=${WORKSPACE}/.ssh/known_hosts <file> <user>@<ip>:~/<file>`**:
   - **Purpose**: Copies a file to the EC2 instance over SSH with host verification.
   - **Usage**: Transfers the `deploy.sh` script to the instance, using the `known_hosts` file for security.
   - **Example**: `scp -i $SSH_KEY -o UserKnownHostsFile=${WORKSPACE}/.ssh/known_hosts deploy.sh ubuntu@18.209.210.162:~/deploy.sh` copies the script securely.

5. **`ssh -i $SSH_KEY -o UserKnownHostsFile=${WORKSPACE}/.ssh/known_hosts <user>@<ip> 'command'`**:
   - **Purpose**: Executes a command on the EC2 instance over SSH with host verification.
   - **Usage**: Runs the `deploy.sh` script on the instance, using the `known_hosts` file for security.
   - **Example**: `ssh -i $SSH_KEY -o UserKnownHostsFile=${WORKSPACE}/.ssh/known_hosts ubuntu@18.209.210.162 'chmod +x ~/deploy.sh && ~/deploy.sh'` executes the script securely.

6. **`rm -rf ${WORKSPACE}/.ssh`**:
   - **Purpose**: Deletes the `.ssh` directory and `known_hosts` file after SSH operations.
   - **Usage**: Cleans up temporary SSH configuration files to maintain security.
   - **Example**: `rm -rf ${WORKSPACE}/.ssh` removes the directory.

7. **`set -e`** (in `deploy.sh`):
   - **Purpose**: Exits the script on any command failure.
   - **Usage**: Ensures the `deploy.sh` script fails fast if any step (e.g., `docker pull`) fails.
   - **Example**: `set -e` at the top of `deploy.sh`.

8. **`chmod +x ~/deploy.sh`** (in `deploy.sh`):
   - **Purpose**: Makes the `deploy.sh` script executable on the EC2 instance.
   - **Usage**: Prepares the script for execution.
   - **Example**: `chmod +x ~/deploy.sh` sets executable permissions.

## Setting Up Nginx as a Reverse Proxy

### Step 1: Install Nginx

1. **Install Nginx**:

   ```bash
   sudo apt update
   sudo apt install nginx -y
   ```

2. **Start Nginx**:

   ```bash
   sudo systemctl start nginx
   sudo systemctl enable nginx
   ```

3. **Verify Nginx is running**:

   ```bash
   sudo systemctl status nginx
   ```

### Step 2: Obtain SSL Certificates with Let's Encrypt

1. **Install Certbot**:

   ```bash
   sudo apt install certbot python3-certbot-nginx -y
   ```

2. **Obtain a certificate**:

   ```bash
   sudo certbot --nginx -d jenkins.teachdev.online
   ```

   - Provide an email address and agree to the terms.
   - Certbot will validate the domain and store certificates in `/etc/letsencrypt/live/jenkins.teachdev.online/`.

3. **Verify certificate files**:

   ```bash
   ls /etc/letsencrypt/live/jenkins.teachdev.online/
   ```

   Expect to see `fullchain.pem` and `privkey.pem`.

4. **Set up automatic renewal**:

   ```bash
   sudo certbot renew --dry-run
   sudo systemctl enable certbot.timer
   sudo systemctl start certbot.timer
   ```

### Step 3: Configure Nginx

1. **Backup the default configuration**:

   ```bash
   sudo mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
   ```

2. **Create a new configuration**:

   ```bash
   sudo nano /etc/nginx/nginx.conf
   ```

3. **Paste the following configuration**:

   ```nginx
   # Nginx configuration for Jenkins reverse proxy with SSL termination
   
   user www-data;
   worker_processes auto;
   error_log /var/log/nginx/error.log warn;
   pid /var/run/nginx.pid;
   
   events {
       worker_connections 1024;
   }
   
   http {
       include /etc/nginx/mime.types;
       default_type application/octet-stream;
   
       log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                       '$status $body_bytes_sent "$http_referer" '
                       '"$http_user_agent" "$http_x_forwarded_for"';
   
       access_log /var/log/nginx/access.log main;
       sendfile on;
       tcp_nopush on;
       keepalive_timeout 65;
       gzip on;
   
       server {
           listen 80;
           server_name jenkins.teachdev.online;
   
           # Redirect HTTP to HTTPS
           return 301 https://$host$request_uri;
       }
   
       server {
           listen 443 ssl;
           server_name jenkins.teachdev.online;
   
           # SSL Configuration
           ssl_certificate /etc/letsencrypt/live/jenkins.teachdev.online/fullchain.pem;
           ssl_certificate_key /etc/letsencrypt/live/jenkins.teachdev.online/privkey.pem;
           ssl_protocols TLSv1.2 TLSv1.3;
           ssl_ciphers EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH;
           ssl_prefer_server_ciphers on;
           ssl_session_cache shared:SSL:10m;
           ssl_session_timeout 1d;
           ssl_session_tickets off;
   
           # Jenkins specific configurations
           location / {
               proxy_pass http://localhost:8080;
               proxy_set_header Host $host;
               proxy_set_header X-Real-IP $remote_addr;
               proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
               proxy_set_header X-Forwarded-Proto $scheme;
   
               # WebSocket support for Jenkins
               proxy_http_version 1.1;
               proxy_set_header Upgrade $http_upgrade;
               proxy_set_header Connection "upgrade";
   
               # Increase buffer size for large headers
               proxy_buffers 8 16k;
               proxy_buffer_size 32k;
   
               # Timeout configurations
               proxy_connect_timeout 60s;
               proxy_send_timeout 60s;
               proxy_read_timeout 60s;
           }
   
           # Security headers
           add_header X-Frame-Options SAMEORIGIN;
           add_header X-Content-Type-Options nosniff;
           add_header X-XSS-Protection "1; mode=block";
           add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   
           # Optional: Enable access logging for Jenkins
           access_log /var/log/nginx/jenkins.access.log main;
           error_log /var/log/nginx/jenkins.error.log warn;
       }
   }
   ```

   Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).


4. **Set permissions**:

   ```bash
   sudo chown root:root /etc/nginx/nginx.conf
   sudo chmod 644 /etc/nginx/nginx.conf
   ```

5. **Test the configuration**:

   ```bash
   sudo nginx -t
   ```

   Ensure it reports:

   ```
   nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
   nginx: configuration file /etc/nginx/nginx.conf test is successful
   ```

6. **Reload Nginx**:

   ```bash
   sudo systemctl reload nginx
   ```

## Troubleshooting

1. **Pipeline Fails at Validate Input**:
   - **Cause**: Invalid parameters (e.g., non-numeric `AWS_ACCOUNT_ID`, invalid `HOST_PORT`).
   - **Solution**: Verify parameters match expected formats.

2. **Assume Role Fails**:
   - **Cause**: Incorrect `sts-user` credentials or `CrossAccountRole` trust policy.
   - **Solution**:
     - Check Jenkins credentials.
     - Verify role ARN and trust policy.

3. **ECR Repository Issues**:
   - **Cause**: Missing `ecr:*` permissions or API errors.
   - **Solution**:
     - Confirm `CrossAccountRole` permissions.
     - Check AWS CLI logs in Jenkins console.

4. **Docker Build/Push Fails**:
   - **Cause**: Missing `Dockerfile` or ECR authentication issues.
   - **Solution**:
     - Ensure `Dockerfile` and app files are in the repository.
     - Verify `aws ecr get-login-password` succeeds.

5. **EC2 Validation Fails**:
   - **Cause**: Invalid `EC2_INSTANCE_ID`, stopped instance, or missing `ec2:DescribeInstances`.
   - **Solution**:
     - Verify instance ID (`i-0fa1266b4dc575aa7`) and state.
     - Check `CrossAccountRole` permissions.

6. **Deploy to EC2 Fails**:
   - **Cause**: SSH issues, incorrect `ec2-key`, or Docker errors.
   - **Solution**:
     - Verify `ec2-key` matches EC2 key pair.
     - Check security group allows port 22 from Jenkins node.
     - Ensure `ssh-keyscan` succeeds (`timeout` installed).
     - Confirm `ubuntu` user has Docker access.

7. **Application Not Accessible**:
   - **Cause**: Container not running, port blocked, or Nginx misconfiguration.
   - **Solution**:
     - Check `docker ps` on EC2.
     - Verify security group allows `HOST_PORT` (e.g., 80).
     - Inspect `nginx.conf` for SPA routing.

8. **Pipeline Errors (Historical)**:
   - **MissingPropertyException for `status`**: Fixed by using `Integer` exit codes or JSON parsing.
   - **Redundant API Calls**: Optimized to single `describe-repositories` and minimal `describe-instances` calls.

## Extensibility

- **Notifications**:
  - Add Gmail email notifications using `emailext` in `post` block:
    ```groovy
    post {
        failure {
            emailext subject: "${env.JOB_NAME} #${env.BUILD_NUMBER} Failed", body: "Check: ${env.BUILD_URL}", to: "your.email@gmail.com"
        }
    }
    ```
  - Requires `Email Extension Plugin`, Gmail App Password, and SMTP setup (`smtp.gmail.com:587`).
- **ECR Cleanup**:
  - Add a stage to delete old images: `aws ecr batch-delete-image`.
- **Session Manager**:
  - Replace SSH with AWS Session Manager for secure EC2 access.
- **ECS Migration**:
  - Transition to ECS for scalable deployments
