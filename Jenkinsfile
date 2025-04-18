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
                    def repoExists = sh(script: """
                        aws ecr describe-repositories \
                            --region ${params.AWS_REGION} \
                            --repository-names ${repoName} \
                            --output json 2>/dev/null || echo '{}'
                    """, returnStdout: true).trim()
                    if (repoExists == '{}') {
                        echo "ECR repository ${repoName} does not exist. Creating..."
                        sh """
                            aws ecr create-repository \
                                --region ${params.AWS_REGION} \
                                --repository-name ${repoName} \
                                --output json
                        """
                    } else {
                        echo "ECR repository ${repoName} already exists."
                    }
                    // Validate repository exists
                    def validateRepo = sh(script: """
                        aws ecr describe-repositories \
                            --region ${params.AWS_REGION} \
                            --repository-names ${repoName} \
                            --output json
                    """, returnStdout: true, returnStatus: true)
                    if (validateRepo != 0) {
                        error "Failed to validate ECR repository ${repoName}."
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
                    sh """
                        aws ecr get-login-password \
                            --region ${params.AWS_REGION} | \
                            docker login \
                                --username AWS \
                                --password-stdin ${params.AWS_ACCOUNT_ID}.dkr.ecr.${params.AWS_REGION}.amazonaws.com
                    """
                    // Tag and push image
                    sh """
                        docker tag my-app:${imageTag}-${env.BUILD_ID} ${fullImage}
                        docker push ${fullImage}
                    """
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
                    if (instanceStatus != 0) {
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
                        // Write SSH commands to a script
                        writeFile file: 'deploy.sh', text: """
                            #!/bin/bash
                            set -e
                            # Authenticate to ECR (instance profile handles permissions)
                            aws ecr get-login-password --region ${params.AWS_REGION} | \
                                docker login --username AWS --password-stdin ${params.AWS_ACCOUNT_ID}.dkr.ecr.${params.AWS_REGION}.amazonaws.com
                            # Pull the new image
                            docker pull ${fullImage}
                            # Stop and remove existing container (if any)
                            docker stop ${containerName} || true
                            docker rm ${containerName} || true
                            # Run the new container
                            docker run -d --name ${containerName} -p ${params.HOST_PORT}:80 ${fullImage}
                            # Prune unused containers and images
                            docker system prune -af || true
                        """
                        // Copy and execute script on EC2
                        sh """
                            chmod 600 \$SSH_KEY
                            scp -i \$SSH_KEY -o StrictHostKeyChecking=no deploy.sh ${params.EC2_SSH_USER}@${env.EC2_IP}:~/deploy.sh
                            ssh -i \$SSH_KEY -o StrictHostKeyChecking=no ${params.EC2_SSH_USER}@${env.EC2_IP} 'chmod +x ~/deploy.sh && ~/deploy.sh'
                            rm -f \$SSH_KEY
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
                sh "docker system prune -af || true"
                // Remove SSH key if it exists
                env.AWS_ACCESS_KEY_ID = ''
                env.AWS_SECRET_ACCESS_KEY = ''
                env.AWS_SESSION_TOKEN = ''
            }
        }
    }
}