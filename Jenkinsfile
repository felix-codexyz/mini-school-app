pipeline {
    agent { label 'docker-node' } // Node with Docker and AWS CLI
    parameters {
        choice(name: 'ENVIRONMENT', choices: ['DEV', 'STAGING', 'PROD'], description: 'Target environment')
        string(name: 'AWS_ACCOUNT_ID', defaultValue: '392102158411', description: 'Target AWS Account ID')
        string(name: 'ROLE_NAME', defaultValue: 'CrossAccountRole', description: 'IAM Role to assume in target account')
        string(name: 'AWS_REGION', defaultValue: 'us-east-1', description: 'AWS Region')
        string(name: 'ECR_REPO_NAME', defaultValue: 'my-app', description: 'Base ECR repository name')
        string(name: 'EC2_INSTANCE_ID', defaultValue: 'i-0fa1266b4dc575aa7', description: 'EC2 Instance ID')
        string(name: 'EC2_SSH_USER', defaultValue: 'ubuntu', description: 'SSH user for EC2 instance')
        string(name: 'HOST_PORT', defaultValue: '80', description: 'Host port for the Docker container')
    }
    stages {
        stage('Validate Input') {
            steps {
                script {
                    if (!params.ENVIRONMENT || !['DEV', 'STAGING', 'PROD'].contains(params.ENVIRONMENT)) {
                        error "Invalid ENVIRONMENT. Must be DEV, STAGING, or PROD."
                    }
                    if (!params.AWS_ACCOUNT_ID || params.AWS_ACCOUNT_ID ==~ /[^0-9]/ || params.AWS_ACCOUNT_ID.length() != 12) {
                        error "Invalid AWS_ACCOUNT_ID. Must be a 12-digit number."
                    }
                    if (!params.ROLE_NAME) {
                        error "ROLE_NAME is required."
                    }
                    if (!params.AWS_REGION) {
                        error "AWS_REGION is required."
                    }
                    if (!params.ECR_REPO_NAME) {
                        error "ECR_REPO_NAME is required."
                    }
                    if (!params.EC2_INSTANCE_ID) {
                        error "EC2_INSTANCE_ID is required."
                    }
                    if (!params.EC2_SSH_USER) {
                        error "EC2_SSH_USER is required."
                    }
                    if (!params.HOST_PORT || params.HOST_PORT ==~ /[^0-9]/ || params.HOST_PORT.toInteger() < 1 || params.HOST_PORT.toInteger() > 65535) {
                        error "Invalid HOST_PORT. Must be a number between 1 and 65535."
                    }
                }
            }
        }
        stage('Assume Role') {
            steps {
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: 'sts-user',
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
                    script {
                        def roleArn = "arn:aws:iam::${params.AWS_ACCOUNT_ID}:role/${params.ROLE_NAME}"
                        def sessionName = "JenkinsSession-${env.BUILD_ID}"
                        def stsOutput = sh(script: """
                            aws sts assume-role \
                                --role-arn ${roleArn} \
                                --role-session-name ${sessionName} \
                                --output json
                        """, returnStdout: true).trim()
                        def stsJson = readJSON text: stsOutput
                        env.AWS_ACCESS_KEY_ID = stsJson.Credentials.AccessKeyId
                        env.AWS_SECRET_ACCESS_KEY = stsJson.Credentials.SecretAccessKey
                        env.AWS_SESSION_TOKEN = stsJson.Credentials.SessionToken
                    }
                }
            }
        }
        stage('Validate/Create ECR Repository') {
            steps {
                script {
                    def repoName = "${params.ECR_REPO_NAME}-${params.ENVIRONMENT.toLowerCase()}"
                    env.ECR_REPO_URL = "${params.AWS_ACCOUNT_ID}.dkr.ecr.${params.AWS_REGION}.amazonaws.com/${repoName}"
                    // Check if repository exists
                    def repoResult = sh(script: """
                        aws ecr describe-repositories \
                            --region ${params.AWS_REGION} \
                            --repository-names ${repoName} \
                            --output json
                    """, returnStatus: true, returnStdout: true)
                    echo "repoResult type: ${repoResult.getClass().name}, value: ${repoResult}"
                    if (repoResult.status != 0) {
                        echo "ECR repository ${repoName} does not exist or access is denied. Attempting to create..."
                        def createResult = sh(script: """
                            aws ecr create-repository \
                                --region ${params.AWS_REGION} \
                                --repository-name ${repoName} \
                                --output json
                        """, returnStatus: true, returnStdout: true)
                        echo "createResult type: ${createResult.getClass().name}, value: ${createResult}"
                        if (createResult.status != 0) {
                            error "Failed to create ECR repository ${repoName}. Check permissions or if it already exists. Output: ${createResult.stdout.trim()}"
                        }
                        echo "ECR repository ${repoName} created successfully."
                    } else {
                        echo "ECR repository ${repoName} already exists."
                    }
                    // Validate repository exists
                    def validateResult = sh(script: """
                        aws ecr describe-repositories \
                            --region ${params.AWS_REGION} \
                            --repository-names ${repoName} \
                            --output json
                    """, returnStatus: true, returnStdout: true)
                    echo "validateResult type: ${validateResult.getClass().name}, value: ${validateResult}"
                    if (validateResult.status != 0) {
                        error "Failed to validate ECR repository ${repoName}. Check permissions. Output: ${validateResult.stdout.trim()}"
                    }
                }
            }
        }
        stage('Build and Push Docker Image') {
            steps {
                script {
                    def imageTag = params.ENVIRONMENT.toLowerCase()
                    def fullImage = "${env.ECR_REPO_URL}:${imageTag}-${env.BUILD_ID}"
                    // Build Docker image
                    sh "docker build -t my-app:${imageTag}-${env.BUILD_ID} ."
                    // Authenticate to ECR
                    def loginResult = sh(script: """
                        aws ecr get-login-password \
                            --region ${params.AWS_REGION} | \
                            docker login \
                                --username AWS \
                                --password-stdin ${params.AWS_ACCOUNT_ID}.dkr.ecr.${params.AWS_REGION}.amazonaws.com
                    """, returnStatus: true, returnStdout: true)
                    echo "loginResult type: ${loginResult.getClass().name}, value: ${loginResult}"
                    if (loginResult.status != 0) {
                        error "Failed to authenticate to ECR. Check permissions for ecr:GetAuthorizationToken. Output: ${loginResult.stdout.trim()}"
                    }
                    // Tag and push image
                    sh "docker tag my-app:${imageTag}-${env.BUILD_ID} ${fullImage}"
                    def pushResult = sh(script: "docker push ${fullImage}", returnStatus: true, returnStdout: true)
                    echo "pushResult type: ${pushResult.getClass().name}, value: ${pushResult}"
                    if (pushResult.status != 0) {
                        error "Failed to push image to ${fullImage}. Check ECR permissions (e.g., ecr:PutImage). Output: ${pushResult.stdout.trim()}"
                    }
                }
            }
        }
        stage('Validate EC2 Instance') {
            steps {
                script {
                    def instanceStatus = sh(script: """
                        aws ec2 describe-instances \
                            --region ${params.AWS_REGION} \
                            --instance-ids ${params.EC2_INSTANCE_ID} \
                            --query 'Reservations[0].Instances[0].State.Name' \
                            --output text
                    """, returnStdout: true, returnStatus: true)
                    echo "instanceStatus type: ${instanceStatus.getClass().name}, value: ${instanceStatus}"
                    if (instanceStatus.status != 0) {
                        error "EC2 instance ${params.EC2_INSTANCE_ID} does not exist or is not accessible."
                    }
                    def state = sh(script: """
                        aws ec2 describe-instances \
                            --region ${params.AWS_REGION} \
                            --instance-ids ${params.EC2_INSTANCE_ID} \
                            --query 'Reservations[0].Instances[0].State.Name' \
                            --output text
                    """, returnStdout: true).trim()
                    if (state != 'running') {
                        error "EC2 instance ${params.EC2_INSTANCE_ID} is not in 'running' state. Current state: ${state}"
                    }
                    // Get public/private IP for SSH
                    env.EC2_IP = sh(script: """
                        aws ec2 describe-instances \
                            --region ${params.AWS_REGION} \
                            --instance-ids ${params.EC2_INSTANCE_ID} \
                            --query 'Reservations[0].Instances[0].PublicIpAddress' \
                            --output text
                    """, returnStdout: true).trim()
                    if (!env.EC2_IP) {
                        env.EC2_IP = sh(script: """
                            aws ec2 describe-instances \
                                --region ${params.AWS_REGION} \
                                --instance-ids ${params.EC2_INSTANCE_ID} \
                                --query 'Reservations[0].Instances[0].PrivateIpAddress' \
                                --output text
                        """, returnStdout: true).trim()
                    }
                    if (!env.EC2_IP) {
                        error "Could not retrieve IP address for EC2 instance ${params.EC2_INSTANCE_ID}."
                    }
                }
            }
        }
        stage('Deploy to EC2') {
            steps {
                withCredentials([sshUserPrivateKey(
                    credentialsId: 'ec2-key',
                    keyFileVariable: 'SSH_KEY',
                    usernameVariable: 'SSH_USERNAME'
                )]) {
                    script {
                        // def repoName = "${params.ECR_REPO_NAME}-${params.ENVIRONMENT.toLowerCase()}"
                        def fullImage = "${env.ECR_REPO_URL}:${params.ENVIRONMENT.toLowerCase()}-${env.BUILD_ID}"
                        def containerName = "my-app-${params.ENVIRONMENT.toLowerCase()}"
                        // Create .ssh directory in workspace
                        sh "mkdir -p ${env.WORKSPACE}/.ssh"
                        // Generate known_hosts file non-interactively
                        def keyscanStatus = sh(script: """
                            timeout 10s ssh-keyscan -t rsa,ecdsa,ed25519 -H ${env.EC2_IP} >> ${env.WORKSPACE}/.ssh/known_hosts
                        """, returnStatus: true)
                        echo "keyscanStatus type: ${keyscanStatus.getClass().name}, value: ${keyscanStatus}"
                        if (keyscanStatus != 0) {
                            error "Failed to fetch EC2 host key for ${env.EC2_IP}. Ensure the instance is reachable and SSH is enabled."
                        }
                        // Write SSH commands to a script
                        writeFile file: 'deploy.sh', text: """
                            #!/bin/bash
                            set -e
                            # Authenticate to ECR (instance profile handles permissions)
                            aws ecr get-login-password --region ${params.AWS_REGION} | \
                                docker login --username AWS --password-stdin ${params.AWS_ACCOUNT_ID}.dkr.ecr.${params.AWS_REGION}.amazonaws.com
                            # Pull the new image
                            docker pull ${fullImage}
                            # Clean up previous images (keep the newly pulled image)
                            docker images ${env.ECR_REPO_URL} --format '{{.Tag}}' | grep -v "${params.ENVIRONMENT.toLowerCase()}-${env.BUILD_ID}" | xargs -I {} docker rmi ${env.ECR_REPO_URL}:{} || true
                            # Stop and remove existing container (if any)
                            docker stop ${containerName} || true
                            docker rm ${containerName} || true
                            # Run the new container
                            docker run -d --name ${containerName} -p ${params.HOST_PORT}:80 ${fullImage}
                            # Prune unused containers
                            docker system prune -f || true
                        """
                        // Copy and execute script on EC2
                        sh """
                            chmod 600 \$SSH_KEY
                            scp -i \$SSH_KEY -o UserKnownHostsFile=${env.WORKSPACE}/.ssh/known_hosts deploy.sh ${params.EC2_SSH_USER}@${env.EC2_IP}:~/deploy.sh
                            ssh -i \$SSH_KEY -o UserKnownHostsFile=${env.WORKSPACE}/.ssh/known_hosts ${params.EC2_SSH_USER}@${env.EC2_IP} 'chmod +x ~/deploy.sh && ~/deploy.sh'
                            rm -f \$SSH_KEY
                            rm -rf ${env.WORKSPACE}/.ssh
                        """
                    }
                }
            }
        }
    }
    post {
        failure {
            echo "Pipeline failed. Please check the logs for details."
        }
        always {
            // Clean up temporary credentials
            script {
                env.AWS_ACCESS_KEY_ID = ''
                env.AWS_SECRET_ACCESS_KEY = ''
                env.AWS_SESSION_TOKEN = ''
            }
        }
    }
}