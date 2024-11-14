pipeline {
    agent any

    environment {
        CLIENT_ID = '123e4567-e89b-12d3-a456-426614174001'
        CLIENT_SECRET = '7a91d1c9-2583-4ef6-8907-7c974f1d6a0e'
        APPLICATION_ID = '673413da502d06461c39d283'
        SCA_API_URL = 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/sca-scans'
        SAST_API_URL = 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/sast-scans'
    }

    stages {
        stage('Clean Up Old Files') {
            steps {
                script {
                    bat 'if exist venv rmdir /S /Q venv'
                    bat 'if exist project.zip del /Q project.zip'
                    bat 'del /Q *.json'
                    bat 'del /Q *.csv'
                    bat 'del /Q *.sh'
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
                    bat 'if exist project_folder rmdir /S /Q project_folder'
                    bat 'mkdir project_folder'
                    powershell '''
                        Get-ChildItem -Exclude .git, venv, project_folder | ForEach-Object {
                            Move-Item $_.FullName project_folder
                        }
                    '''
                    bat 'powershell Compress-Archive -Path project_folder\\* -DestinationPath project.zip'
                }
            }
        }

        stage('Perform SCA Scan') {
            steps {
                script {
                    def response = bat(script: """
                        powershell -Command "
                        $client = New-Object System.Net.Http.HttpClient
                        $client.DefaultRequestHeaders.Add('Client-ID', '${CLIENT_ID}')
                        $client.DefaultRequestHeaders.Add('Client-Secret', '${CLIENT_SECRET}')
                        $content = New-Object System.Net.Http.MultipartFormDataContent
                        $fileStream = [System.IO.File]::OpenRead('project.zip')
                        $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
                        $fileContent.Headers.ContentDisposition = New-Object System.Net.Http.Headers.ContentDispositionHeaderValue('form-data')
                        $fileContent.Headers.ContentDisposition.Name = 'projectZipFile'
                        $fileContent.Headers.ContentDisposition.FileName = 'project.zip'
                        $content.Add($fileContent)
                        $content.Add((New-Object System.Net.Http.StringContent('${APPLICATION_ID}')), 'applicationId')
                        $content.Add((New-Object System.Net.Http.StringContent('New SCA Scan from Jenkins Pipeline')), 'scanName')
                        $content.Add((New-Object System.Net.Http.StringContent('python')), 'language')
                        $response = $client.PostAsync('${SCA_API_URL}', $content).Result
                        $result = $response.Content.ReadAsStringAsync().Result
                        Write-Output $result
                        "
                    """, returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def canProceedSCA = jsonResponse.canProceed
                    def vulnsTable = jsonResponse.vulnsTable

                    echo "Vulnerabilities found during SCA:"
                    echo "${vulnsTable}"

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
                    def response = bat(script: """
                        powershell -Command "
                        $client = New-Object System.Net.Http.HttpClient
                        $client.DefaultRequestHeaders.Add('Client-ID', '${CLIENT_ID}')
                        $client.DefaultRequestHeaders.Add('Client-Secret', '${CLIENT_SECRET}')
                        $content = New-Object System.Net.Http.MultipartFormDataContent
                        $fileStream = [System.IO.File]::OpenRead('project.zip')
                        $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
                        $fileContent.Headers.ContentDisposition = New-Object System.Net.Http.Headers.ContentDispositionHeaderValue('form-data')
                        $fileContent.Headers.ContentDisposition.Name = 'projectZipFile'
                        $fileContent.Headers.ContentDisposition.FileName = 'project.zip'
                        $content.Add($fileContent)
                        $content.Add((New-Object System.Net.Http.StringContent('${APPLICATION_ID}')), 'applicationId')
                        $content.Add((New-Object System.Net.Http.StringContent('New SAST Scan from Jenkins Pipeline')), 'scanName')
                        $content.Add((New-Object System.Net.Http.StringContent('python')), 'language')
                        $response = $client.PostAsync('${SAST_API_URL}', $content).Result
                        $result = $response.Content.ReadAsStringAsync().Result
                        Write-Output $result
                        "
                    """, returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def canProceedSAST = jsonResponse.canProceed
                    def vulnsTable = jsonResponse.vulnsTable

                    echo "Vulnerabilities found during SAST:"
                    echo "${vulnsTable}"

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
                bat 'python -m venv venv'
                bat 'venv\\Scripts\\activate && python -m pip install --upgrade pip'
            }
        }

        stage('Install Dependencies') {
            steps {
                bat 'venv\\Scripts\\activate && pip install -r requirements.txt'
            }
        }

        // Additional stages (e.g., deploy) can be added here
    }
}
