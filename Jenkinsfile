pipeline {
    agent any

    environment {
        CLIENT_ID = '654621'
        CLIENT_SECRET = '7a965dsf4e'
        APPLICATION_ID = '673kajdh'
        SCA_API_URL = 'https://test.com/api/sca-scans'
        SAST_API_URL = 'htttps://test.com/api/sast-scans'
    }

    stages {
        stage('Ensure curl is Installed') {
            steps {
                script {
                    // Install curl if it's not already installed (Linux example)
                    sh '''
                    if ! command -v curl &> /dev/null; then
                        echo "curl could not be found, installing..."
                        sudo apt-get update && sudo apt-get install -y curl
                    fi
                    '''
                }
            }
        }

        stage('Clean Up Old Files') {
            steps {
                script {
                    sh 'rm -rf venv'
                    sh 'rm -rf project.zip'
                    sh 'rm -rf *.json'
                    sh 'rm -rf *.csv'
                    sh 'rm -rf *.sh'
                }
            }
        }

        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('Create ZIP Files') {
            steps {
                script {
                    sh 'rm -rf project_folder'
                    sh 'mkdir project_folder'
                    sh 'find . -maxdepth 1 -not -name "." -not -name ".." -not -name ".git" -not -name "venv" -not -name "project_folder" -exec mv {} project_folder/ \\;'
                    sh 'zip -r project.zip project_folder'
                }
            }
        }

        stage('Perform SCA Scan') {
            steps {
                script {
                    def response = sh(script: """
                        #!/bin/bash
                        curl -v -X POST \
                        -H "Client-ID: ${CLIENT_ID}" \
                        -H "Client-Secret: ${CLIENT_SECRET}" \
                        -F "projectZipFile=@project.zip" \
                        -F "applicationId=${APPLICATION_ID}" \
                        -F "scanName=New SCA Scan from Jenkins Pipeline" \
                        -F "language=python" \
                        "${SCA_API_URL}"
                    """, returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def canProceedSCA = jsonResponse.canProceed
                    def vulnsTable = jsonResponse.vulnsTable

                    def cleanVulnsTable = vulnsTable.replaceAll(/\x1B\[[;0-9]*m/, '')

                    echo "Vulnerabilities found during SCA:"
                    echo "${cleanVulnsTable}"

                    env.CAN_PROCEED_SCA = canProceedSCA.toString()
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
                script {
                    def response = sh(script: """
                        #!/bin/bash
                        curl -v -X POST \
                        -H "Client-ID: ${CLIENT_ID}" \
                        -H "Client-Secret: ${CLIENT_SECRET}" \
                        -F "projectZipFile=@project.zip" \
                        -F "applicationId=${APPLICATION_ID}" \
                        -F "scanName=New SAST Scan from Jenkins Pipeline" \
                        -F "language=python" \
                        "${SAST_API_URL}"
                    """, returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def canProceedSAST = jsonResponse.canProceed
                    def vulnsTable = jsonResponse.vulnsTable

                    def cleanVulnsTable = vulnsTable.replaceAll(/\x1B\[[;0-9]*m/, '')

                    echo "Vulnerabilities found during SAST:"
                    echo "${cleanVulnsTable}"

                    env.CAN_PROCEED_SAST = canProceedSAST.toString()
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
                sh '. venv/bin/activate && pip install --upgrade pip'
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '. venv/bin/activate && pip install -r requirements.txt'
            }
        }

        // Additional stages (e.g., deploy) can be added here
    }
}

