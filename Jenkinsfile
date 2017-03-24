node {
    def createvirtualenv = ''
    def activatevirtualenv = ''
    if (isUnix()) {
        createvirtualenv = 'rm -r $JENKINS_HOME/venv/$JOB_NAME || true && virtualenv $JENKINS_HOME/venv/$JOB_NAME'
        activatevirtualenv = '. $JENKINS_HOME/venv/$JOB_NAME/bin/activate'
    } else {
        createvirtualenv = 'rmdir /s /q %JENKINS_HOME%\\venv\\%JOB_NAME% || true && virtualenv %JENKINS_HOME%\\venv\\%JOB_NAME%'
        activatevirtualenv = 'call %JENKINS_HOME%\\venv\\%JOB_NAME%\\Scripts\\activate.bat'
    }

    stage('checkout') {
        checkout scm
        if (isUnix()) {
            sh 'hg --config extensions.purge= purge --all'
        } else {
            bat 'hg --config extensions.purge= purge --all'
        }
    }
    stage('virtual env') {
        def virtualenvscript = """$createvirtualenv
            $activatevirtualenv
            python -m pip install --upgrade pip
            pip install --upgrade setuptools
            pip install --upgrade pylint
            pip install --upgrade pytest-cov
            """
        if (isUnix()) {
            virtualenvscript += """
                pip install --upgrade python-ldap
                pip install --upgrade python-pam
                """
            sh virtualenvscript
        } else {
            bat virtualenvscript
        }
    }
    stage('setup') {
        def virtualenvscript = """$activatevirtualenv
            pip install --upgrade -e .
            pip install -r dev_requirements.txt
            python setup.py compile_catalog
            """
        if (isUnix()) {
            sh virtualenvscript
        } else {
            bat virtualenvscript
        }
        stash name: 'kallithea', useDefaultExcludes: false
    }
    stage('pylint') {
        sh script: """$activatevirtualenv
            pylint -j 0 --disable=C -f parseable kallithea > pylint.out
            """, returnStatus: true
        archiveArtifacts 'pylint.out'
        try {
            step([$class: 'WarningsPublisher', canComputeNew: false, canResolveRelativePaths: false, defaultEncoding: '', excludePattern: '', healthy: '', includePattern: '', messagesPattern: '', parserConfigurations: [[parserName: 'PyLint', pattern: 'pylint.out']], unHealthy: ''])
        } catch (java.lang.IllegalArgumentException exc) {
            echo "You need to install the 'Warnings Plug-in' to display the pylint report."
            currentBuild.result = 'UNSTABLE'
            echo "Caught: ${exc}"
        }
    }
    def pytests = [:]
    pytests['sqlite'] = {
        ws {
            deleteDir()
            unstash name: 'kallithea'
            if (isUnix()) {
                sh script: """$activatevirtualenv
                    py.test -p no:sugar --cov-config .coveragerc --junit-xml=pytest_sqlite.xml --cov=kallithea --cov-report xml
                    """, returnStatus: true
            } else {
                bat script: """$activatevirtualenv
                    py.test -p no:sugar --cov-config .coveragerc --junit-xml=pytest_sqlite.xml --cov=kallithea --cov-report xml
                    """, returnStatus: true
            }
            sh 'sed --in-place "s/\\(classname=[\'\\"]\\)/\\1SQLITE./g" pytest_sqlite.xml'
            archiveArtifacts 'pytest_sqlite.xml'
            junit 'pytest_sqlite.xml'
            try {
                step([$class: 'CoberturaPublisher', autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: 'coverage.xml', failNoReports: false, failUnhealthy: false, failUnstable: false, maxNumberOfBuilds: 0, onlyStable: false, zoomCoverageChart: false])
            } catch (java.lang.IllegalArgumentException exc) {
                echo "You need to install the pipeline compatible 'CoberturaPublisher Plug-in' to display the coverage report."
                currentBuild.result = 'UNSTABLE'
                echo "Caught: ${exc}"
            }
        }
    }
    if (isUnix()) {
        pytests['de'] = {
            ws {
                deleteDir()
                unstash name: 'kallithea'
                withEnv(['LANG=de_DE.UTF-8',
                    'LANGUAGE=de',
                    'LC_ADDRESS=de_DE.UTF-8',
                    'LC_IDENTIFICATION=de_DE.UTF-8',
                    'LC_MEASUREMENT=de_DE.UTF-8',
                    'LC_MONETARY=de_DE.UTF-8',
                    'LC_NAME=de_DE.UTF-8',
                    'LC_NUMERIC=de_DE.UTF-8',
                    'LC_PAPER=de_DE.UTF-8',
                    'LC_TELEPHONE=de_DE.UTF-8',
                    'LC_TIME=de_DE.UTF-8',
                ]) {
                    sh script: """$activatevirtualenv
                        py.test -p no:sugar --cov-config .coveragerc --junit-xml=pytest_de.xml --cov=kallithea --cov-report xml
                        """, returnStatus: true
                }
                sh 'sed --in-place "s/\\(classname=[\'\\"]\\)/\\1DE./g" pytest_de.xml'
                archiveArtifacts 'pytest_de.xml'
                junit 'pytest_de.xml'
            }
        }
        pytests['mysql'] = {
            ws {
                deleteDir()
                unstash name: 'kallithea'
                sh """$activatevirtualenv
                    pip install --upgrade MySQL-python
                    """
                withEnv(['TEST_DB=mysql://kallithea:kallithea@jenkins_mysql/kallithea_test?charset=utf8']) {
                    if (isUnix()) {
                        sh script: """$activatevirtualenv
                            py.test -p no:sugar --cov-config .coveragerc --junit-xml=pytest_mysql.xml --cov=kallithea --cov-report xml
                            """, returnStatus: true
                    } else {
                        bat script: """$activatevirtualenv
                            py.test -p no:sugar --cov-config .coveragerc --junit-xml=pytest_mysql.xml --cov=kallithea --cov-report xml
                            """, returnStatus: true
                    }
                }
                sh 'sed --in-place "s/\\(classname=[\'\\"]\\)/\\1MYSQL./g" pytest_mysql.xml'
                archiveArtifacts 'pytest_mysql.xml'
                junit 'pytest_mysql.xml'
            }
        }
        pytests['postgresql'] = {
            ws {
                deleteDir()
                unstash name: 'kallithea'
                sh """$activatevirtualenv
                    pip install --upgrade psycopg2
                    """
                withEnv(['TEST_DB=postgresql://kallithea:kallithea@jenkins_postgresql/kallithea_test']) {
                    if (isUnix()) {
                        sh script: """$activatevirtualenv
                            py.test -p no:sugar --cov-config .coveragerc --junit-xml=pytest_postgresql.xml --cov=kallithea --cov-report xml
                            """, returnStatus: true
                    } else {
                        bat script: """$activatevirtualenv
                            py.test -p no:sugar --cov-config .coveragerc --junit-xml=pytest_postgresql.xml --cov=kallithea --cov-report xml
                            """, returnStatus: true
                    }
                }
                sh 'sed --in-place "s/\\(classname=[\'\\"]\\)/\\1POSTGRES./g" pytest_postgresql.xml'
                archiveArtifacts 'pytest_postgresql.xml'
                junit 'pytest_postgresql.xml'
            }
        }
    }
    stage('Tests') {
        parallel pytests
    }
}
