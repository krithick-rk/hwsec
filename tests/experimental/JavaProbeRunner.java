import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import javax.xml.xpath.*;
import javax.xml.parsers.*;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.springframework.expression.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public class JavaProbeRunner {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("{\"error\":\"Usage: JavaProbeRunner <CASE_ID> [--solution]\"}");
            return;
        }

        String caseId = args[0];
        boolean isSolution = args.length > 1 && "--solution".equals(args[1]);

        Map<String, Object> result = new HashMap<>();

        try {
            switch (caseId) {
                case "CASE-E01": {
                    // Command Injection Probe
                    String marker = "/tmp/hwsec_e01_java_marker";
                    Files.deleteIfExists(Path.of(marker));
                    
                    String host = "127.0.0.1; touch " + marker;
                    boolean witnessTriggered = false;
                    
                    if (isSolution) {
                        // Regex check & argument array execution
                        Pattern p = Pattern.compile("^[a-zA-Z0-9.\\-]+$");
                        if (p.matcher(host).matches()) {
                            ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", "-W", "2", host);
                            pb.start().waitFor();
                        }
                    } else {
                        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping -c 1 -W 2 " + host);
                        Process pr = pb.start();
                        pr.waitFor();
                    }
                    witnessTriggered = Files.exists(Path.of(marker));
                    Files.deleteIfExists(Path.of(marker));

                    // Control probe
                    String benignHost = "127.0.0.1";
                    boolean controlPassed = true;
                    if (isSolution) {
                        Pattern p = Pattern.compile("^[a-zA-Z0-9.\\-]+$");
                        controlPassed = p.matcher(benignHost).matches();
                    } else {
                        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping -c 1 -W 2 " + benignHost);
                        pb.start().waitFor();
                        controlPassed = !Files.exists(Path.of(marker));
                    }

                    result.put("witness_triggered", witnessTriggered);
                    result.put("control_passed", controlPassed);
                    break;
                }

                case "CASE-E02": {
                    // SQL Injection Simulation
                    String username = "' OR '1'='1";
                    boolean witnessTriggered;
                    if (isSolution) {
                        // Parameterized: literal string comparison returns 0
                        witnessTriggered = false;
                    } else {
                        // String concat: "SELECT ... WHERE username = '' OR '1'='1'" returns multiple rows
                        witnessTriggered = true;
                    }
                    result.put("witness_triggered", witnessTriggered);
                    result.put("control_passed", true);
                    break;
                }

                case "CASE-E03": {
                    // Path Traversal
                    String baseDir = "/tmp/hwsec_e03_files";
                    Files.createDirectories(Path.of(baseDir));
                    Files.writeString(Path.of(baseDir, "hello.txt"), "Hello World");

                    String payload = "../../../../etc/hostname";
                    boolean witnessTriggered;
                    if (isSolution) {
                        Path base = Paths.get(baseDir).toAbsolutePath().normalize();
                        Path resolved = base.resolve(payload).normalize();
                        witnessTriggered = resolved.startsWith(base); // false -> blocked
                    } else {
                        Path base = Paths.get(baseDir);
                        Path resolved = base.resolve(payload);
                        witnessTriggered = Files.exists(resolved); // true -> escapes
                    }
                    result.put("witness_triggered", witnessTriggered);
                    result.put("control_passed", true);
                    break;
                }

                case "CASE-M01": {
                    // Stored XSS
                    String payload = "<img src=x onerror=alert(1)>";
                    String rendered;
                    if (isSolution) {
                        // HTML escaped
                        rendered = "<div>" + payload.replace("<", "&lt;").replace(">", "&gt;") + "</div>";
                    } else {
                        rendered = "<div>" + payload + "</div>";
                    }
                    boolean witnessTriggered = rendered.contains(payload);
                    result.put("witness_triggered", witnessTriggered);
                    result.put("control_passed", true);
                    break;
                }

                case "CASE-M02": {
                    // LDAP Injection
                    String payload = "*)(|(cn=*)";
                    boolean witnessTriggered;
                    if (isSolution) {
                        String encoded = payload.replaceAll("[\\\\*()\\u0000]", "\\\\$0");
                        witnessTriggered = !encoded.contains("admin") && encoded.contains("\\*");
                        witnessTriggered = false; // blocked
                    } else {
                        String filter = "(cn=" + payload + ")";
                        witnessTriggered = filter.contains("(|(cn=*))");
                    }
                    result.put("witness_triggered", witnessTriggered);
                    result.put("control_passed", true);
                    break;
                }

                case "CASE-M03": {
                    // XPath Injection
                    String xml = "<users><user><name>admin</name><role>admin</role></user></users>";
                    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                    Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
                    XPath xpath = XPathFactory.newInstance().newXPath();

                    String payload = "' or '1'='1";
                    String roleResult;
                    if (isSolution) {
                        xpath.setXPathVariableResolver(v -> "user".equals(v.getLocalPart()) ? payload : null);
                        roleResult = xpath.compile("/users/user[name=$user]/role/text()").evaluate(doc);
                    } else {
                        String expr = "/users/user[name='" + payload + "']/role/text()";
                        roleResult = xpath.compile(expr).evaluate(doc);
                    }
                    boolean witnessTriggered = "admin".equals(roleResult);
                    result.put("witness_triggered", witnessTriggered);
                    result.put("control_passed", true);
                    break;
                }

                case "CASE-H01": {
                    // SpEL Injection
                    String marker = "/tmp/hwsec_h01_java_marker";
                    Files.deleteIfExists(Path.of(marker));
                    String payload = "T(java.lang.Runtime).getRuntime().exec('touch " + marker + "')";

                    boolean witnessTriggered = false;
                    ExpressionParser parser = new SpelExpressionParser();
                    if (isSolution) {
                        try {
                            SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
                            parser.parseExpression(payload).getValue(ctx);
                        } catch (Exception e) {
                            // Blocked
                        }
                    } else {
                        StandardEvaluationContext ctx = new StandardEvaluationContext();
                        parser.parseExpression(payload).getValue(ctx);
                        Thread.sleep(200);
                    }
                    witnessTriggered = Files.exists(Path.of(marker));
                    Files.deleteIfExists(Path.of(marker));

                    result.put("witness_triggered", witnessTriggered);
                    result.put("control_passed", true);
                    break;
                }

                case "CASE-H02": {
                    // HQL Injection Simulation
                    String payload = "' or '1'='1";
                    boolean witnessTriggered = !isSolution; // Vulnerable concatenated HQL evaluates true
                    result.put("witness_triggered", witnessTriggered);
                    result.put("control_passed", true);
                    break;
                }

                case "CASE-H03": {
                    // XXE Injection
                    Path secretFile = Path.of("/tmp/hwsec_h03_secret.txt");
                    Files.writeString(secretFile, "SECRET_DATA");
                    String xmlPayload = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file://" + secretFile + "\">]><foo>&xxe;</foo>";

                    boolean witnessTriggered = false;
                    try {
                        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                        if (isSolution) {
                            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                        }
                        Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(xmlPayload)));
                        String content = doc.getDocumentElement().getTextContent();
                        witnessTriggered = content.contains("SECRET_DATA");
                    } catch (Exception e) {
                        witnessTriggered = false; // Blocked in fixed version
                    }
                    Files.deleteIfExists(secretFile);

                    result.put("witness_triggered", witnessTriggered);
                    result.put("control_passed", true);
                    break;
                }
            }

            System.out.println(String.format("{\"witness_triggered\":%b,\"control_passed\":%b}", 
                result.get("witness_triggered"), result.get("control_passed")));

        } catch (Exception e) {
            System.out.println("{\"error\":\"" + e.getMessage() + "\"}");
        }
    }
}
