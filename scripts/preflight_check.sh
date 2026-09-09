#!/bin/bash
set -e

export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GALETTE_JDK=/home/intern/hwsec-workspace/galette-inst-jdk8
export GALETTE_AGENT=/home/intern/hwsec-workspace/galette/galette-agent/target/galette-agent-1.0.0-SNAPSHOT.jar
export STANDARD_JAVA8=/usr/lib/jvm/java-8-openjdk-amd64

echo "=== ENVIRONMENT PREFLIGHT CHECK ==="
echo "JAVA_HOME: $JAVA_HOME"
java -version 2>&1 | head -n 1
mvn -version 2>&1 | head -n 1

echo "STANDARD_JAVA8: $STANDARD_JAVA8"
"$STANDARD_JAVA8/bin/java" -version 2>&1 | head -n 1

echo "GALETTE_JDK: $GALETTE_JDK"
echo "GALETTE_AGENT: $GALETTE_AGENT"

if [ -x "$GALETTE_JDK/bin/java" ]; then
    echo "GALETTE_JDK executable: OK"
else
    echo "GALETTE_JDK executable: MISSING"
    exit 1
fi

if [ -f "$GALETTE_AGENT" ]; then
    echo "GALETTE_AGENT jar: OK"
else
    echo "GALETTE_AGENT jar: MISSING"
    exit 1
fi

mkdir -p /tmp/galette-cache
echo "Testing GALETTE_JDK with galette.cache, bootclasspath, and javaagent..."
"$GALETTE_JDK/bin/java" -Dgalette.cache=/tmp/galette-cache -Xbootclasspath/a:"$GALETTE_AGENT" -javaagent:"$GALETTE_AGENT" -version 2>&1 | head -n 3

echo "=== PREFLIGHT CHECK ALL PASSED ==="
