
pipeline {
    agent any

    parameters {
        choice(name: 'PIPELINE_MODE', choices: ['deploy', 'scan'], description: 'Run deployment or an API-submitted scan')
        choice(name: 'SCAN_TARGET_TYPE', choices: ['website', 'repository'], description: 'Target type for scan mode')
        string(name: 'SCAN_ID', defaultValue: '', description: 'Backend-owned scan UUID')
        string(name: 'SCAN_TARGET', defaultValue: '', description: 'Validated website or repository URL from the API')
        string(name: 'WAZUH_MANAGER_SERVER', defaultValue: '', description: 'Optional private Wazuh Manager address')
    }

    environment {
        GEMINI_API_KEY = credentials('GEMINI_API_KEY')
        TARGET_URL = "${params.SCAN_TARGET}"
    }

    stages {

        stage('SonarQube Analysis') {
            when {
                expression { params.PIPELINE_MODE == 'deploy' }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    script {
                        def scannerHome = tool 'Sonar-Server'

                        withSonarQubeEnv('SonarQube') {
                            sh "${scannerHome}/bin/sonar-scanner"
                        }
                    }
                }
            }
        }

        stage('Build and Deploy Backend') {
            when {
                expression { params.PIPELINE_MODE == 'deploy' }
            }
            steps {
                withCredentials([
                    string(credentialsId: 'DJANGO_SECRET_KEY', variable: 'DJANGO_SECRET_KEY'),
                    string(credentialsId: 'DJANGO_ALLOWED_HOSTS', variable: 'DJANGO_ALLOWED_HOSTS'),
                    string(credentialsId: 'CORS_ALLOWED_ORIGINS', variable: 'CORS_ALLOWED_ORIGINS')
                ]) {
                    sh '''
                        set -e

                        echo "Building Docker image..."

                        docker build -t intellisecops-backend:latest ./backend

                        echo "Stopping old container..."

                        docker stop intellisecops-backend || true
                        docker rm intellisecops-backend || true

                        echo "Creating persistent Docker volumes..."

                        docker volume create intellisecops-data
                        docker volume create intellisecops-logs

                        echo "Fixing database volume permissions..."

                        docker run --rm \
                            --user root \
                            -v intellisecops-data:/data \
                            intellisecops-backend:latest \
                            sh -c "chown -R app:app /data"

                        echo "Starting new backend container..."

                        set +x

                        docker run -d \
                            --name intellisecops-backend \
                            --restart unless-stopped \
                            -p 127.0.0.1:5000:5000 \
                            -v intellisecops-data:/data \
                            -v intellisecops-logs:/app/logs \
                            -e GEMINI_API_KEY="$GEMINI_API_KEY" \
                            -e DJANGO_DEBUG=false \
                            -e DJANGO_SECRET_KEY="$DJANGO_SECRET_KEY" \
                            -e DJANGO_ALLOWED_HOSTS="$DJANGO_ALLOWED_HOSTS" \
                            -e CORS_ALLOWED_ORIGINS="$CORS_ALLOWED_ORIGINS" \
                            intellisecops-backend:latest

                        set -x

                        echo "Waiting for backend..."

                        for i in $(seq 1 15); do
                            if curl -sf http://127.0.0.1:5000 > /dev/null; then
                                echo "Backend is up."
                                break
                            fi

                            echo "Backend not ready yet ($i/15)..."
                            sleep 3
                        done

                        echo "Checking backend..."

                        curl --fail http://127.0.0.1:5000

                        echo "Running database migrations..."

                        docker exec intellisecops-backend \
                            python manage.py migrate --noinput

                        echo "Backend deployed successfully!"
                    '''
                }
            }
        }

        stage('Deploy Wazuh Log Agent') {
            when {
                expression {
                    params.PIPELINE_MODE == 'deploy' &&
                    params.WAZUH_MANAGER_SERVER?.trim()
                }
            }
            steps {
                sh '''
                    set -e

                    docker build -t intellisecops-wazuh-agent:4.14.10 ./deploy/wazuh

                    docker stop intellisecops-wazuh-agent || true
                    docker rm intellisecops-wazuh-agent || true

                    docker run -d \
                        --name intellisecops-wazuh-agent \
                        --restart unless-stopped \
                        -e WAZUH_MANAGER_SERVER="$WAZUH_MANAGER_SERVER" \
                        -v intellisecops-logs:/var/log/intellisecops:ro \
                        intellisecops-wazuh-agent:4.14.10
                '''
            }
        }

        stage('Start User Scan') {
            when {
                expression { params.PIPELINE_MODE == 'scan' }
            }
            steps {
                withCredentials([
                    string(credentialsId: 'SCAN_PIPELINE_TOKEN', variable: 'SCAN_PIPELINE_TOKEN'),
                    string(credentialsId: 'SCAN_API_BASE_URL', variable: 'SCAN_API_BASE_URL')
                ]) {
                    sh '''
                        set +x

                        CALLBACK_BODY=$(python3 -c 'import json,os; print(json.dumps({"status":"running","target_type":os.environ["SCAN_TARGET_TYPE"],"target":os.environ["SCAN_TARGET"]}))')

                        curl --fail --silent --show-error \
                            -X POST "$SCAN_API_BASE_URL/api/scans/$SCAN_ID/pipeline-result/" \
                            -H "X-Scan-Pipeline-Token: $SCAN_PIPELINE_TOKEN" \
                            -H "Content-Type: application/json" \
                            --data "$CALLBACK_BODY"
                    '''
                }
            }
        }

        stage('SonarQube Repository Scan') {
            when {
                beforeAgent true
                expression {
                    params.PIPELINE_MODE == 'scan' &&
                    params.SCAN_TARGET_TYPE == 'repository'
                }
            }
            agent {
                label 'isolated-scan-worker'
            }
            options {
                timeout(time: 30, unit: 'MINUTES')
            }
            steps {
                script {
                    def scannerHome = tool 'Sonar-Server'

                    dir('submitted-source') {
                        deleteDir()

                        sh 'git clone --depth 1 --single-branch -- "$SCAN_TARGET" .'

                        def projectDirectory = pwd()

                        withEnv([
                            "SONAR_PROJECT_KEY=IntelliSecOps-${params.SCAN_ID}",
                            "SONAR_PROJECT_DIRECTORY=${projectDirectory}"
                        ]) {
                            withSonarQubeEnv('SonarQube') {
                                sh """
                                    "${scannerHome}/bin/sonar-scanner" \
                                      -Dsonar.projectKey="\$SONAR_PROJECT_KEY" \
                                      -Dsonar.projectName="\$SONAR_PROJECT_KEY" \
                                      -Dsonar.sources=. \
                                      -Dsonar.scm.disabled=true
                                """

                                sh 'python3 ../scripts/sonar_issues_report.py > ../scan-result.json'
                            }
                        }
                    }

                    stash name: 'intellisecops-sonar-report',
                        includes: 'scan-result.json'
                }
            }
        }

        stage('OWASP ZAP Scan') {
            when {
                beforeAgent true
                expression {
                    params.PIPELINE_MODE == 'scan' &&
                    params.SCAN_TARGET_TYPE == 'website'
                }
            }
            agent {
                label 'isolated-scan-worker'
            }
            options {
                timeout(time: 30, unit: 'MINUTES')
            }
            steps {
                sh '''
                    set -e

                    echo "Preparing ZAP reports directory..."

                    mkdir -p zap-reports
                    chmod 777 zap-reports

                    echo "Starting OWASP ZAP scan..."

                    docker run --rm \
                        -u root \
                        -v "$(pwd)/zap-reports:/zap/wrk" \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py \
                        -t "$TARGET_URL" \
                        -r report.html \
                        -J report.json || true

                    echo "ZAP scan completed."

                    ls -lah zap-reports
                '''

                stash name: 'intellisecops-zap-report',
                    includes: 'zap-reports/report.json'
            }
        }

        stage('Send User Scan Report to Django') {
            when {
                beforeAgent true
                expression {
                    params.PIPELINE_MODE == 'scan'
                }
            }
            agent {
                label 'isolated-scan-worker'
            }
            steps {
                script {
                    if (params.SCAN_TARGET_TYPE == 'website') {
                        unstash 'intellisecops-zap-report'

                        sh '''
                            python3 -c 'import json,os,sys; json.dump({"status":"completed","scan_type":"ZAP","target_type":os.environ["SCAN_TARGET_TYPE"],"target":os.environ["SCAN_TARGET"],"report":json.load(sys.stdin)},sys.stdout)' \
                                < zap-reports/report.json > scan-result.json
                        '''
                    } else {
                        unstash 'intellisecops-sonar-report'
                    }
                }

                withCredentials([
                    string(credentialsId: 'SCAN_PIPELINE_TOKEN', variable: 'SCAN_PIPELINE_TOKEN'),
                    string(credentialsId: 'SCAN_API_BASE_URL', variable: 'SCAN_API_BASE_URL')
                ]) {
                    sh '''
                        set +x

                        HTTP_STATUS=$(curl -s -o django_scan_response.json -w "%{http_code}" -X POST \
                            "$SCAN_API_BASE_URL/api/scans/$SCAN_ID/pipeline-result/" \
                            --connect-timeout 10 \
                            --max-time 120 \
                            -H "X-Scan-Pipeline-Token: $SCAN_PIPELINE_TOKEN" \
                            -H "Content-Type: application/json" \
                            --data-binary @scan-result.json)

                        if [ "$HTTP_STATUS" -lt 200 ] || [ "$HTTP_STATUS" -ge 300 ]; then
                            echo "Django rejected the scan result (HTTP $HTTP_STATUS)."
                            exit 1
                        fi

                        echo "Scan report sent successfully."
                    '''
                }
            }
        }

        stage('Archive Reports') {
            when {
                expression { params.PIPELINE_MODE == 'scan' }
            }
            steps {
                echo 'Archiving scan reports...'

                archiveArtifacts artifacts: 'zap-reports/*,scan-result.json',
                    allowEmptyArchive: true

                echo 'Reports archived successfully!'
            }
        }
    }

    post {
        failure {
            script {
                if (params.PIPELINE_MODE == 'scan' && params.SCAN_ID) {
                    withCredentials([
                        string(credentialsId: 'SCAN_PIPELINE_TOKEN', variable: 'SCAN_PIPELINE_TOKEN'),
                        string(credentialsId: 'SCAN_API_BASE_URL', variable: 'SCAN_API_BASE_URL')
                    ]) {
                        sh '''
                            set +x

                            CALLBACK_BODY=$(python3 -c 'import json,os; print(json.dumps({"status":"failed","error":"The isolated scanner pipeline failed. Check the restricted Jenkins build log.","target_type":os.environ.get("SCAN_TARGET_TYPE",""),"target":os.environ.get("SCAN_TARGET","")}))')

                            curl --silent --show-error \
                                -X POST "$SCAN_API_BASE_URL/api/scans/$SCAN_ID/pipeline-result/" \
                                -H "X-Scan-Pipeline-Token: $SCAN_PIPELINE_TOKEN" \
                                -H "Content-Type: application/json" \
                                --data "$CALLBACK_BODY" \
                                || true
                        '''
                    }
                }

                echo 'PIPELINE FAILED! Check Jenkins console output.'
            }
        }

        success {
            echo '======================================'
            echo 'PIPELINE COMPLETED SUCCESSFULLY!'
            echo '======================================'

            script {
                try {
                    slackSend(
                        tokenCredentialId: 'slack-token',
                        channel: '#all-pipeline-notifier',
                        color: 'good',
                        message: "IntelliSecOps Pipeline SUCCESS - Build #${env.BUILD_NUMBER} - ${env.BUILD_URL}"
                    )
                } catch (err) {
                    echo "Slack notification failed: ${err}"
                }
            }
        }
    }
}
