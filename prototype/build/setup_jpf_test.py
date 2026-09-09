sat_java = """
public class TestConcolicSat {
    public static void checkVuln(int x) {
        if (x > 10) {
            assert false : "SECURITY_VIOLATION_SAT";
        }
    }
    public static void main(String[] args) {
        checkVuln(15);
    }
}
"""

unsat_java = """
public class TestConcolicUnsat {
    public static void checkSafe(int x) {
        int num = 106;
        if ((7 * 18) + num <= 200) {
            assert false : "SECURITY_VIOLATION_SAT";
        }
    }
    public static void main(String[] args) {
        checkSafe(5);
    }
}
"""

sat_jpf = """target = TestConcolicSat
classpath = /tmp
symbolic.method = TestConcolicSat.checkVuln(sym)
symbolic.dp = z3
"""

unsat_jpf = """target = TestConcolicUnsat
classpath = /tmp
symbolic.method = TestConcolicUnsat.checkSafe(sym)
symbolic.dp = z3
"""

with open('/tmp/TestConcolicSat.java', 'w') as f:
    f.write(sat_java)
with open('/tmp/TestConcolicUnsat.java', 'w') as f:
    f.write(unsat_java)
with open('/tmp/TestSat.jpf', 'w') as f:
    f.write(sat_jpf)
with open('/tmp/TestUnsat.jpf', 'w') as f:
    f.write(unsat_jpf)

print("Generated test files in /tmp")
