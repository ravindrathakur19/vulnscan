// VulnScan Pro - DevSecOps CI/CD pipeline
//
// Required Jenkins credentials (Manage Jenkins -> Credentials):
//   dockerhub-creds        (Username with password) - DockerHub login
//   kubeconfig-vulnscan    (Secret file)             - K3s kubeconfig for the target cluster
//
// Required Jenkins plugins: Docker Pipeline, Pipeline Utility Steps, Kubernetes CLI (or just kubectl on PATH).
// GitHub webhook: repo Settings -> Webhooks -> Payload URL = http(s)://<jenkins-host>/github-webhook/,
// content type application/json, event: "Just the push event". Job must have
// "GitHub hook trigger for GITScm polling" enabled.
//
// Nothing here hardcodes a secret: DockerHub and kubeconfig both come from the
// Jenkins credential store, injected only for the step that needs them.

pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }

    parameters {
        string(name: 'DOCKERHUB_REPO', defaultValue: 'ravi12t/vuln-scanner', description: 'DockerHub repository')
        string(name: 'TRIVY_SEVERITY_GATE', defaultValue: 'CRITICAL,HIGH', description: 'Severities that fail the build if found')
        booleanParam(name: 'DEPLOY_TO_K8S', defaultValue: true, description: 'Run the Kubernetes deploy stage')
    }

    environment {
        IMAGE_TAG = "${env.GIT_COMMIT ? env.GIT_COMMIT.take(7) : 'local'}"
        IMAGE     = "${params.DOCKERHUB_REPO}:${IMAGE_TAG}"
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                sh 'git rev-parse --short HEAD'
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''
                    python3 -m venv .venv
                    . .venv/bin/activate
                    pip install --upgrade pip
                    pip install -r requirements-dev.txt
                '''
            }
        }

        stage('Unit Tests - pytest') {
            steps {
                sh '''
                    . .venv/bin/activate
                    pytest --cov=. --cov-report=xml --junitxml=pytest-report.xml -v
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'pytest-report.xml'
                }
            }
        }

        stage('Docker Build') {
            steps {
                // Immutable tag from the commit SHA, never only "latest"
                sh "docker build -t ${IMAGE} -t ${params.DOCKERHUB_REPO}:latest ."
            }
        }

        stage('Trivy Image Security Scan') {
            steps {
                sh """
                    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                        -v \$(pwd)/trivy-cache:/root/.cache/ \
                        aquasec/trivy:latest image \
                        --severity ${params.TRIVY_SEVERITY_GATE} \
                        --exit-code 1 \
                        --no-progress \
                        --format table \
                        ${IMAGE}
                """
            }
            // A non-zero exit from Trivy fails this stage and stops the pipeline
            // before anything is pushed to DockerHub - this is the security gate.
        }

        stage('DockerHub Push') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'dockerhub-creds',
                                                  usernameVariable: 'DOCKER_USER',
                                                  passwordVariable: 'DOCKER_PASS')]) {
                    sh '''
                        echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
                    '''
                    sh "docker push ${IMAGE}"
                    sh "docker push ${params.DOCKERHUB_REPO}:latest"
                    sh 'docker logout'
                }
            }
        }

        stage('Deploy to Kubernetes') {
            when { expression { return params.DEPLOY_TO_K8S } }
            steps {
                withCredentials([file(credentialsId: 'kubeconfig-vulnscan', variable: 'KUBECONFIG')]) {
                    sh """
                        kubectl set image deployment/scanner-deployment vuln-scanner=${IMAGE} --record
                        kubectl rollout status deployment/scanner-deployment --timeout=120s
                    """
                }
            }
        }

        stage('Deployment Health Check') {
            when { expression { return params.DEPLOY_TO_K8S } }
            steps {
                withCredentials([file(credentialsId: 'kubeconfig-vulnscan', variable: 'KUBECONFIG')]) {
                    sh '''
                        kubectl get pods -l app=vuln-scanner
                        kubectl get endpoints scanner-service
                        # Fail the build if no pod reports Ready
                        kubectl wait --for=condition=Ready pod -l app=vuln-scanner --timeout=90s
                    '''
                }
            }
        }
    }

    post {
        always {
            sh 'docker image prune -f || true'
        }
        failure {
            echo "Pipeline failed at stage: ${env.STAGE_NAME}. Nothing further was pushed or deployed."
        }
    }
}
