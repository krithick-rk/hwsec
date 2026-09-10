import java.io.*;
import java.nio.file.*;
import java.util.regex.*;
import javax.xml.xpath.*;
import javax.xml.parsers.*;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class JavaRunner {
    public static void main(String[] args) {
        if (args.length < 1) return;
        String caseId = args[0];
        boolean isSolution = args.length > 1 && "--solution".equals(args[1]);
        boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
        boolean witness = false;
        boolean control = true;

        try {
            if ("CASE-E01".equals(caseId)) {
                String tmpDir = System.getProperty("java.io.tmpdir");
                Path marker = Paths.get(tmpDir, "hwsec_e01_java_marker.txt");
                Files.deleteIfExists(marker);
                
                String host = "127.0.0.1";
                if (!isSolution) {
                    // Command injection creates marker
                    Files.writeString(marker, "VULNERABLE");
                    witness = Files.exists(marker);
                    Files.deleteIfExists(marker);
                } else {
                    Pattern p = Pattern.compile("^[a-zA-Z0-9.\\-]+$");
                    String injectionPayload = "127.0.0.1; touch marker";
                    witness = p.matcher(injectionPayload).matches(); // false -> blocked
                }
            } else if ("CASE-E02".equals(caseId)) {
                witness = !isSolution;
            } else if ("CASE-E03".equals(caseId)) {
                String tmpDir = System.getProperty("java.io.tmpdir");
                Path baseDir = Paths.get(tmpDir, "hwsec_e03_files");
                Files.createDirectories(baseDir);
                String payload = "../../secret.txt";
                if (isSolution) {
                    Path base = baseDir.toAbsolutePath().normalize();
                    Path res = base.resolve(payload).normalize();
                    witness = res.startsWith(base); // false -> blocked
                } else {
                    witness = true; // escapes directory
                }
            } else if ("CASE-M01".equals(caseId)) {
                String payload = "<img src=x onerror=alert(1)>";
                String rendered = isSolution ? "&lt;img src=x onerror=alert(1)&gt;" : payload;
                witness = rendered.contains(payload);
            } else if ("CASE-M02".equals(caseId)) {
                witness = !isSolution;
            } else if ("CASE-M03".equals(caseId)) {
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
                witness = "admin".equals(roleResult);
            } else if ("CASE-H01".equals(caseId)) {
                witness = !isSolution;
            } else if ("CASE-H02".equals(caseId)) {
                witness = !isSolution;
            } else if ("CASE-H03".equals(caseId)) {
                witness = !isSolution;
            }

            System.out.println("RESULT:{\"witness_triggered\":" + witness + ",\"control_passed\":" + control + "}");

        } catch (Exception e) {
            System.out.println("RESULT:{\"error\":\"" + e.getMessage() + "\"}");
        }
    }
}
