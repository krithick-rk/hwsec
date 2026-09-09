#!/bin/bash
set -e
mkdir -p /home/intern/hwsec-workspace/BenchmarkJava/src/main/java/org/owasp/benchmark/harness
mkdir -p /home/intern/hwsec-workspace/BenchmarkJava/src/main/java/org/owasp/benchmark/concolic

cp /mnt/e/Intern/hwsec/prototype/harnesses/HarnessRunner.java /home/intern/hwsec-workspace/BenchmarkJava/src/main/java/org/owasp/benchmark/harness/
cp /mnt/e/Intern/hwsec/prototype/harnesses/TaintHarnessRunner.java /home/intern/hwsec-workspace/BenchmarkJava/src/main/java/org/owasp/benchmark/harness/
cp /mnt/e/Intern/hwsec/prototype/harnesses/SecuritySinkObserver.java /home/intern/hwsec-workspace/BenchmarkJava/src/main/java/org/owasp/benchmark/harness/
cp /mnt/e/Intern/hwsec/prototype/harnesses/ConcolicTargetHarness.java /home/intern/hwsec-workspace/BenchmarkJava/src/main/java/org/owasp/benchmark/concolic/

SERVLET_JAR="/home/intern/.m2/repository/javax/servlet/javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar"
CLASSES="/home/intern/hwsec-workspace/BenchmarkJava/target/classes"

/usr/lib/jvm/java-8-openjdk-amd64/bin/javac -g:lines,vars,source -cp "$SERVLET_JAR:$CLASSES" -d "$CLASSES" \
    /home/intern/hwsec-workspace/BenchmarkJava/src/main/java/org/owasp/benchmark/harness/*.java \
    /home/intern/hwsec-workspace/BenchmarkJava/src/main/java/org/owasp/benchmark/concolic/*.java

echo "All harnesses including TaintHarnessRunner compiled with -g successfully."
