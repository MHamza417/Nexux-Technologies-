
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

                    echo "Starting OWASP ZAP Baseline scan (limited crawl and passive rules)..."

                    set +e
                    docker run --rm \
                        -u root \
                        -v "$(pwd)/zap-reports:/zap/wrk" \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py \
                        -t "$TARGET_URL" \
                        -r report.html \
                        -J report.json
                    zap_status=$?
                    set -e

                    if [ "$zap_status" -gt 2 ]; then
                        echo "ZAP failed to complete (exit code $zap_status)."
                        exit 1
                    fi
                    if [ ! -s zap-reports/report.json ]; then
                        echo "ZAP did not produce a non-empty JSON report."
                        exit 1
                    fi

                    docker run --rm -u root -v "$PWD/zap-reports:/zap/wrk" --entrypoint chown ghcr.io/zaproxy/zaproxy:stable -R $(id -u):$(id -g) /zap/wrk
                    echo "ZAP Baseline report generated (exit code $zap_status)."

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
                            --max-time 300 \
                            --retry 2 \
                            --retry-delay 5 \
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

        stage('Deploy Compose Stack') {
            when {
                expression {
                    params.PIPELINE_MODE == 'deploy' &&
                    (
                        env.BRANCH_NAME == 'main' ||
                        env.GIT_BRANCH == 'main' ||
                        env.GIT_BRANCH == 'origin/main' ||
                        env.GIT_BRANCH == 'refs/remotes/origin/main'
                    )
                }
            }
            options {
                timeout(time: 30, unit: 'MINUTES')
            }
            steps {
                sshagent(credentials: ['app-server-ssh']) {
                    sh '''
                        set -e
                        ssh -o StrictHostKeyChecking=accept-new ubuntu@13.63.222.33 \
                            'cd /home/ubuntu/Nexux-Technologies- && git pull --ff-only origin main && docker compose build backend frontend && docker compose up -d --no-deps --force-recreate backend frontend && docker image prune -f'
                    '''
                }
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
