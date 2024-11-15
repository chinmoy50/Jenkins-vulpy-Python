pipeline {
    agent any

    environment {
        SCA_API_URL = 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/sca-scans'
        SAST_API_URL = 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/sast-scans'
    }

    stages {
        stage('Clean Up Old Files') {
            steps {
                sh 'rm -rf venv project.zip *.json *.csv *.sh'
            }
        }

        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('Create ZIP Files') {
            steps {
                sh '''
                    rm -rf project_folder
                    mkdir project_folder
                    find . -maxdepth 1 -not -name "." -not -name ".." -not -name ".git" -not -name "venv" -not -name "project_folder" -exec mv {} project_folder/ \\;
                    zip -r project.zip project_folder
                '''
            }
        }

        stage('Perform SCA Scan') {
            steps {
                withCredentials([
                    string(credentialsId: 'client-id', variable: 'CLIENT_ID'),
                    string(credentialsId: 'client-secret', variable: 'CLIENT_SECRET'),
                    string(credentialsId: 'application-id', variable: 'APPLICATION_ID')
                ]) {
                    script {
                        def response = sh(script: """
                            curl -s -X POST \
                            -H "Client-ID: ${CLIENT_ID}" \
                            -H "Client-Secret: ${CLIENT_SECRET}" \
                            -F "projectZipFile=@project.zip" \
                            -F "applicationId=${APPLICATION_ID}" \
                            -F "scanName=New SCA Scan from Jenkins Pipeline" \
                            -F "language=python" \
                            "${SCA_API_URL}"
                        """, returnStdout: true).trim()

                        def jsonResponse = readJSON(text: response)
                        env.CAN_PROCEED_SCA = jsonResponse.canProceed ? "true" : "false"
                        
                        echo "Vulnerabilities found during SCA: ${jsonResponse.vulnsTable}"
                    }
                }
            }
        }

        stage('Check SCA Result') {
            when {
                expression { return env.CAN_PROCEED_SCA != 'true' }
            }
            steps {
                error "SCA scan failed. Deployment cancelled."
            }
        }

        stage('Perform SAST Scan') {
            when {
                expression { return env.CAN_PROCEED_SCA == 'true' }
            }
            steps {
                withCredentials([
                    string(credentialsId: 'client-id', variable: 'CLIENT_ID'),
                    string(credentialsId: 'client-secret', variable: 'CLIENT_SECRET'),
                    string(credentialsId: 'application-id', variable: 'APPLICATION_ID')
                ]) {
                    script {
                        def response = sh(script: """
                            curl -s -X POST \
                            -H "Client-ID: ${CLIENT_ID}" \
                            -H "Client-Secret: ${CLIENT_SECRET}" \
                            -F "projectZipFile=@project.zip" \
                            -F "applicationId=${APPLICATION_ID}" \
                            -F "scanName=New SAST Scan from Jenkins Pipeline" \
                            -F "language=python" \
                            "${SAST_API_URL}"
                        """, returnStdout: true).trim()

                        def jsonResponse = readJSON(text: response)
                        env.CAN_PROCEED_SAST = jsonResponse.canProceed ? "true" : "false"
                        
                        echo "Vulnerabilities found during SAST: ${jsonResponse.vulnsTable}"
                    }
                }
            }
        }

        stage('Check SAST Result') {
            when {
                expression { return env.CAN_PROCEED_SAST != 'true' }
            }
            steps {
                error "SAST scan failed. Deployment cancelled."
            }
        }

        stage('Set Up Python') {
            steps {
                sh 'python3 -m venv venv'
                sh './venv/bin/pip install --upgrade pip'
            }
        }

        stage('Install Dependencies') {
            steps {
                sh './venv/bin/pip install -r requirements.txt'
            }
        }
    }
}
