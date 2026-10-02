pipeline {
    agent any

    environment {
        GEMINI_API_KEY = credentials('GEMINI_API_KEY')
        TARGET_URL    = 'http://13.63.222.33'
    }

    stages {

        stage('SonarQube Analysis') {
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
            steps {
                sh '''
                    echo "Building Docker image..."

                    docker build -t intellisecops-backend:latest ./backend

                    echo "Stopping old container..."

                    docker stop intellisecops-backend || true
                    docker rm intellisecops-backend || true

                    docker volume create intellisecops-data

                    echo "Starting new backend container..."

                    docker run -d \
                        --name intellisecops-backend \
                        -p 5000:5000 \
                        -v intellisecops-data:/data \
                        -e GEMINI_API_KEY="$GEMINI_API_KEY" \
                        intellisecops-backend:latest

                    echo "Waiting for backend..."

                    for i in $(seq 1 10); do
                        if curl -sf http://127.0.0.1:5000 > /dev/null; then
                            echo "Backend is up."
                            break
                        fi
                        echo "Backend not ready yet, retrying ($i/10)..."
                        sleep 3
                    done

                    echo "Checking backend health..."

                    curl -f http://127.0.0.1:5000

                    echo "Running database migrations..."
                    docker exec intellisecops-backend python manage.py migrate --noinput

                    echo "Backend deployed successfully!"
                '''
            }
        }

        stage('OWASP ZAP Scan') {
            steps {
                sh '''
                    echo "Preparing ZAP reports directory..."

                    mkdir -p zap-reports
                    chmod 777 zap-reports

                    echo "Starting OWASP ZAP scan..."

                    docker run --rm \
                        -u root \
                        -v "$(pwd)/zap-reports:/zap/wrk" \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py \
                        -t $TARGET_URL \
                        -r report.html \
                        -J report.json || true

                    echo "ZAP scan completed."

                    echo "Generated reports:"

                    ls -lah zap-reports
                '''
            }
        }

        stage('SQLMap Scan') {
            steps {
                sh '''
                    echo "Preparing SQLMap reports directory..."

                    mkdir -p sqlmap-reports
                    chmod 777 sqlmap-reports

                    echo "Starting SQLMap database scan..."

                    if [ ! -d "sqlmap-tool" ]; then
                        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-tool
                    fi

                    python3 sqlmap-tool/sqlmap.py \
                        -u "$TARGET_URL/api/analyze-report/?id=1" \
                        --batch \
                        --level=2 \
                        --risk=1 \
                        -v 1 | tee sqlmap-reports/sqlmap_output.log || true

                    echo "SQLMap scan completed."

                    echo "Parsing SQLMap output into JSON..."
                    python3 parse_sqlmap.py \
                        "$TARGET_URL/api/analyze-report/?id=1" \
                        sqlmap-reports/sqlmap_output.log \
                        sqlmap-reports/sqlmap_findings.json

                    echo "Generated reports:"
                    ls -lah sqlmap-reports || true
                '''
            }
        }

        stage('Send SQLMap Report to Django') {
            steps {
                sh '''
                    echo "Sending SQLMap findings to Django API..."

                    if [ -f sqlmap-reports/sqlmap_findings.json ]; then

                        HTTP_STATUS=$(curl -s -o django_sqlmap_response.json -w "%{http_code}" -X POST \
                            http://127.0.0.1:5000/api/analyze-sqlmap-report/ \
                            -H "Content-Type: application/json" \
                            --data-binary @sqlmap-reports/sqlmap_findings.json)

                        echo "Django responded with HTTP $HTTP_STATUS"
                        echo "Response body:"
                        cat django_sqlmap_response.json
                        echo ""

                        if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
                            echo "SQLMap report successfully sent to Django!"
                        else
                            echo "Django rejected the SQLMap report. Backend logs:"
                            docker logs intellisecops-backend --tail 50 || true
                        fi

                    else
                        echo "WARNING: sqlmap_findings.json was not generated, skipping."
                    fi
                '''
            }
        }

        stage('Send Report to Django') {
            steps {
                sh '''
                    echo "Sending ZAP report to Django API..."

                    if [ -f zap-reports/report.json ]; then

                        HTTP_STATUS=$(curl -s -o django_response.json -w "%{http_code}" -X POST \
                            http://127.0.0.1:5000/api/analyze-report/ \
                            -H "Content-Type: application/json" \
                            --data-binary @zap-reports/report.json)

                        echo "Django responded with HTTP $HTTP_STATUS"
                        echo "Response body:"
                        cat django_response.json
                        echo ""

                        if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
                            echo "ZAP report successfully sent to Django!"
                        else
                            echo "Django rejected the report. Backend logs:"
                            docker logs intellisecops-backend --tail 50 || true
                            exit 1
                        fi

                    else

                        echo "ERROR: ZAP report.json was not generated!"
                        exit 1

                    fi
                '''
            }
        }

        stage('Smart Security Gate') {
            steps {
                script {
                    def highRiskCount = sh(
                        script: '''
                            python3 -c "
import json
try:
    with open('zap-reports/report.json') as f:
        data = json.load(f)
    count = 0
    sites = data.get('site', [])
    if isinstance(sites, list):
        for s in sites:
            for alert in s.get('alerts', []):
                risk = alert.get('riskdesc', '')
                if risk.startswith('High') or risk.startswith('Critical'):
                    count += 1
    print(count)
except Exception as e:
    print(0)
"
                        ''',
                        returnStdout: true
                    ).trim()

                    echo "High/Critical risk vulnerabilities found: ${highRiskCount}"

                    if (highRiskCount.toInteger() > 0) {
                        env.SECURITY_GATE_STATUS = "BLOCKED"
                        error("Smart Security Gate: Deployment BLOCKED — ${highRiskCount} high/critical risk vulnerability(ies) detected!")
                    } else {
                        env.SECURITY_GATE_STATUS = "PASSED"
                        echo "Smart Security Gate: No high/critical vulnerabilities found. Deployment allowed."
                    }
                }
            }
        }

        stage('Archive Reports') {
            steps {
                echo 'Archiving ZAP and SQLMap reports...'

                archiveArtifacts artifacts: 'zap-reports/*, sqlmap-reports/**',
                    allowEmptyArchive: true

                echo 'Reports archived successfully!'
            }
        }
    }

    post {
        success {
            echo '======================================'
            echo 'PIPELINE COMPLETED SUCCESSFULLY!'
            echo '======================================'

            slackSend(
                tokenCredentialId: 'slack-token',
                channel: '#all-pipeline-notifier',
                color: 'good',
                message: "✅ *IntelliSecOps Pipeline SUCCESS*\nBuild: #${env.BUILD_NUMBER}\nSecurity Gate: ${env.SECURITY_GATE_STATUS ?: 'N/A'}\nDetails: ${env.BUILD_URL}"
            )

            emailext(
                subject: "✅ IntelliSecOps Build #${env.BUILD_NUMBER} - SUCCESS",
                body: """
                    <h2>Pipeline Completed Successfully</h2>
                    <p><b>Build:</b> #${env.BUILD_NUMBER}</p>
                    <p><b>Security Gate Status:</b> ${env.SECURITY_GATE_STATUS ?: 'N/A'}</p>
                    <p><b>Build URL:</b> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                """,
                mimeType: 'text/html',
                to: 'hamzamayo570@gmail.com'
            )
        }

        failure {
            echo '======================================'
            echo 'PIPELINE FAILED!'
            echo 'Check the Jenkins console output.'
            echo '======================================'

            slackSend(
                tokenCredentialId: 'slack-token',
                channel: '#all-pipeline-notifier',
                color: 'danger',
                message: "❌ *IntelliSecOps Pipeline FAILED*\nBuild: #${env.BUILD_NUMBER}\nDetails: ${env.BUILD_URL}"
            )

            emailext(
                subject: "🚨 IntelliSecOps Build #${env.BUILD_NUMBER} - FAILED",
                body: """
                    <h2>Pipeline Failed</h2>
                    <p><b>Build:</b> #${env.BUILD_NUMBER}</p>
                    <p><b>Security Gate Status:</b> ${env.SECURITY_GATE_STATUS ?: 'N/A'}</p>
                    <p>Check console output for details:</p>
                    <p><a href="${env.BUILD_URL}console">${env.BUILD_URL}console</a></p>
                """,
                mimeType: 'text/html',
                to: 'hamzamayo570@gmail.com'
            )
        }
    }
}