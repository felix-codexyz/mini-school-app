pipeline {
    agent { label: 'node-ubuntu-aws-01 '}
    parameters {
        choice(name: 'ENVIRONMENT', choices: ['DEV', 'STAGING', 'PROD'], description: 'Target environment for deployment')
        string(name: 'AWS_ACCOUNT_ID', defaultValue: '123456789101', description: 'Target AWS Account ID')
        string(name: 'ROLE_NAME', defaultValue: 'CrossAccountRole', description: 'IAM Role to Assume in the Target Account')
        string(name: 'AWS_REGION', defaultValue: 'eu-west-2', description: 'AWS Region')
        string(name: 'ECR_REPO_NAME', defaultValue: 'classof25', description: 'Repo Name')
        string(name: 'EC2_INSTANCE_ID', defaultValue: 'i-1234567890abcdef0', description: 'EC2 Instance ID')
        string(name: 'EC2_SSH_USER', defaultValue: 'ubuntu', description: 'SSH User for EC2 Instance')
        string(name: 'HOST_PORT', defaultValue: '80', description: "Host Port for Docker Container")

    }
    stages {
        stage('Validate Input') {
            steps {
                script {
                    if (!params.ENVIRONMENT || !['DEV', 'STAGING', 'PROD'].contains(params.ENVIRONMENT)) {
                        error "Invalid ENVIRONMENT parameter. Must be one of: DEV, STAGING, PROD."
                    }
                    if (!params.AWS_ACCOUNT_ID || params.AWS_ACCOUNT_ID ==~ /[^0-9]/ || params.AWS_ACCOUNT_ID.length() != 12) {
                        error "Invalid AWS_ACCOUNT_ID parameter. Must be a 12-digit number."
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
                        error "Invalid HOST_PORT parameter. Must be a number between 1 and 65535."
                    }
                }
            }
        }
    }
}