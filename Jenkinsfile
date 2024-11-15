pipeline {
    agent any

    environment {
        CLIENT_ID = '654621'
        CLIENT_SECRET = '7a965dsf4e'
        APPLICATION_ID = '673kajdh'
        SCA_API_URL = 'https://test.com/api/sca-scans'
        SAST_API_URL = 'https://test.com/api/sast-scans'  // Fixed typo from 'htttps'
    }

    stages {
        // Ensure curl is installed (updated to use apt-get)
        stage('Ensure curl is Installed') {
            steps {
                script {
                    // Check if curl is available
                    def curlAvailable = sh(script: 'command -v curl', returnStatus: true) == 0
                    if (!curlAvailable) {
                        echo "curl could not be found. Installing..."
                        // Try to install curl using apt-get (for Debian-based systems)
                        sh 'apt-get update && apt-get install -y curl'
                    } else {
                        echo "curl is already installed."
                    }
                }
            }
        }

        // Clean up old files
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

        // Checkout code from SCM
        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        // Create ZIP file
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

        // Perform SCA scan
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

        // Check SCA result
        stage('Check SCA Result') {
            when {
                expression { return env.CAN_PROCEED_SCA != 'true' }
            }
            steps {
                error "SCA scan failed. Deployment cancelled."
            }
        }

        // Perform SAST scan (with debugging and additional checks)
        stage('Perform SAST Scan') {
            when {
                expression { return env.CAN_PROCEED_SCA == 'true' }
            }
            steps {
                script {
                    echo "Starting SAST scan..."

                    // Perform the SAST API request
                    def response = sh(script: """
                        #!/bin/bash
                        echo "Sending request to SAST API..."
                        curl -v -X POST \
                        -H "Client-ID: ${CLIENT_ID}" \
                        -H "Client-Secret: ${CLIENT_SECRET}" \
                        -F "projectZipFile=@project.zip" \
                        -F "applicationId=${APPLICATION_ID}" \
                        -F "scanName=New SAST Scan from Jenkins Pipeline" \
                        -F "language=python" \
                        "${SAST_API_URL}"
                    """, returnStdout: true, returnStatus: true)

                    // Log the response
                    echo "SAST API Response: ${response}"

                    // Parse the response
                    def jsonResponse = readJSON(text: response)
                    echo "Parsed JSON Response: ${jsonResponse}"

                    // Check if 'canProceed' field exists
                    def canProceedSAST = jsonResponse?.canProceed
                    if (canProceedSAST == null) {
                        error "SAST response did not contain 'canProceed' field."
                    }

                    def vulnsTable = jsonResponse.vulnsTable
                    if (vulnsTable == null) {
                        error "SAST response did not contain 'vulnsTable'."
                    }

                    // Clean up vulnerability table from escape sequences
                    def cleanVulnsTable = vulnsTable.replaceAll(/\x1B\[[;0-9]*m/, '')

                    // Output vulnerabilities
                    echo "Vulnerabilities found during SAST:"
                    echo "${cleanVulnsTable}"

                    // Set environment variable based on SAST result
                    env.CAN_PROCEED_SAST = canProceedSAST.toString()

                    // Additional logic to check if the scan succeeded or failed
                    if (canProceedSAST != 'true') {
                        error "SAST scan failed. Deployment cancelled."
                    }
                }
            }
        }

        // Check SAST result
        stage('Check SAST Result') {
            when {
                expression { return env.CAN_PROCEED_SAST != 'true' }
            }
            steps {
                error "SAST scan failed. Deployment cancelled."
            }
        }

        // Set up Python environment
        stage('Set Up Python') {
            steps {
                sh 'python3 -m venv venv'
                sh '. venv/bin/activate && pip install --upgrade pip'
            }
        }

        // Install dependencies
        stage('Install Dependencies') {
            steps {
                sh '. venv/bin/activate && pip install -r requirements.txt'
            }
        }

        // Additional stages (e.g., deploy) can be added here
    }
}
