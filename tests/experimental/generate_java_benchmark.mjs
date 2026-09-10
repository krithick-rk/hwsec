/**
 * Generator script for Java / Spring Boot 3 Benchmark
 */
import fs from 'fs';
import path from 'path';

const BENCH_DIR = path.resolve('hwsec_java_benchmark');

function ensureDir(p) {
    if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function writeFile(relPath, content) {
    const full = path.join(BENCH_DIR, relPath);
    ensureDir(path.dirname(full));
    fs.writeFileSync(full, content.trim() + '\n', 'utf-8');
}

console.log('[*] Generating Java Spring Boot Benchmark at: ' + BENCH_DIR);

// 1. Root README
writeFile('README.md', `# HWSEC Artificial Vulnerability Benchmark (Java / Spring Boot)

A self-contained, reproducible set of intentionally vulnerable projects
designed for advanced operational testing of the HWSEC security-operations framework.

## Structure
benchmark_targets/   — Vulnerable Spring Boot projects (HWSEC scans ONLY this directory)
solutions/            — Fixed versions of each project
answer_key/           — Manifest, expected findings, witness catalog
scripts/              — Validation and run-all scripts
`);

// 2. Answer Key
const manifest = {
  "benchmark_version": "1.0-java",
  "cases": [
    {
      "case_id": "CASE-E01",
      "difficulty": "easy",
      "vulnerability_class": "CWE-78 OS Command Injection",
      "primary_entry_point": "POST /api/diagnostic/ping",
      "source_to_sink": "PingRequest.getHost() -> ProcessBuilder(\"sh\", \"-c\", \"ping \" + host)",
      "exploit_witness": "POST /api/diagnostic/ping with body {\"host\":\"127.0.0.1; touch /tmp/hwsec_e01_java_marker\"}",
      "expected_security_effect": "Marker file /tmp/hwsec_e01_java_marker is created",
      "negative_control": "POST /api/diagnostic/ping with body {\"host\":\"127.0.0.1\"}",
      "fixed_solution_path": "solutions/easy/CASE-E01-command-injection-FIXED",
      "expected_hwsec_classification": "DETECTED"
    },
    {
      "case_id": "CASE-E02",
      "difficulty": "easy",
      "vulnerability_class": "CWE-89 SQL Injection",
      "primary_entry_point": "GET /api/users/search?username=",
      "source_to_sink": "@RequestParam username -> jdbc.queryForList(\"SELECT ... WHERE username = '\" + username + \"'\")",
      "exploit_witness": "GET /api/users/search?username=' OR '1'='1",
      "expected_security_effect": "Returns all users instead of one",
      "negative_control": "GET /api/users/search?username=alice",
      "fixed_solution_path": "solutions/easy/CASE-E02-sql-injection-FIXED",
      "expected_hwsec_classification": "DETECTED"
    },
    {
      "case_id": "CASE-E03",
      "difficulty": "easy",
      "vulnerability_class": "CWE-22 Path Traversal",
      "primary_entry_point": "GET /api/files/download?filename=",
      "source_to_sink": "@RequestParam filename -> Paths.get(BASE_DIR).resolve(filename) -> Files.readString()",
      "exploit_witness": "GET /api/files/download?filename=../../../../etc/hostname",
      "expected_security_effect": "Reads /etc/hostname",
      "negative_control": "GET /api/files/download?filename=hello.txt",
      "fixed_solution_path": "solutions/easy/CASE-E03-path-traversal-FIXED",
      "expected_hwsec_classification": "DETECTED"
    },
    {
      "case_id": "CASE-M01",
      "difficulty": "medium",
      "vulnerability_class": "CWE-79 XSS (Stored)",
      "primary_entry_point": "POST /api/messages -> GET /api/messages/{id}",
      "source_to_sink": "@RequestBody content -> db.put(id, content) -> db.get(id) -> String return",
      "exploit_witness": "POST <img src=x onerror=alert(1)> -> GET /api/messages/1",
      "expected_security_effect": "Unescaped HTML returned in response",
      "negative_control": "POST hello -> GET /api/messages/1",
      "fixed_solution_path": "solutions/medium/CASE-M01-xss-stored-FIXED",
      "expected_hwsec_classification": "DETECTED"
    },
    {
      "case_id": "CASE-M02",
      "difficulty": "medium",
      "vulnerability_class": "CWE-90 LDAP Injection",
      "primary_entry_point": "GET /api/auth/lookup?username=",
      "source_to_sink": "@RequestParam username -> \"(cn=\" + username + \")\" -> executeLdapSearch()",
      "exploit_witness": "GET /api/auth/lookup?username=*)(|(cn=*)",
      "expected_security_effect": "Lookup succeeds for non-existent user",
      "negative_control": "GET /api/auth/lookup?username=nonexistent",
      "fixed_solution_path": "solutions/medium/CASE-M02-ldap-injection-FIXED",
      "expected_hwsec_classification": "DETECTED"
    },
    {
      "case_id": "CASE-M03",
      "difficulty": "medium",
      "vulnerability_class": "CWE-643 XPath Injection",
      "primary_entry_point": "GET /api/xml/search?username=",
      "source_to_sink": "@RequestParam username -> xpath.compile(\"/users/user[name='\" + username + \"']/role/text()\")",
      "exploit_witness": "GET /api/xml/search?username=' or '1'='1",
      "expected_security_effect": "Returns admin role without exact username match",
      "negative_control": "GET /api/xml/search?username=nonexistent",
      "fixed_solution_path": "solutions/medium/CASE-M03-xpath-injection-FIXED",
      "expected_hwsec_classification": "DETECTED"
    },
    {
      "case_id": "CASE-H01",
      "difficulty": "hard",
      "vulnerability_class": "CWE-94 Code Injection (SpEL)",
      "primary_entry_point": "POST /api/rules/evaluate",
      "source_to_sink": "@RequestBody expression -> parser.parseExpression(expression) -> exp.getValue(StandardEvaluationContext)",
      "exploit_witness": "POST body {\"expression\":\"T(java.lang.Runtime).getRuntime().exec('touch /tmp/hwsec_h01_java_marker')\"}",
      "expected_security_effect": "Arbitrary code execution creating a marker file",
      "negative_control": "POST body {\"expression\":\"#user\"}",
      "fixed_solution_path": "solutions/hard/CASE-H01-spel-injection-FIXED",
      "expected_hwsec_classification": "DETECTED"
    },
    {
      "case_id": "CASE-H02",
      "difficulty": "hard",
      "vulnerability_class": "CWE-89 SQL Injection (HQL)",
      "primary_entry_point": "GET /api/products/search?name=",
      "source_to_sink": "@RequestParam name -> entityManager.createQuery(\"... WHERE p.name = '\" + name + \"'\")",
      "exploit_witness": "GET /api/products/search?name=' or '1'='1",
      "expected_security_effect": "Returns all products",
      "negative_control": "GET /api/products/search?name=Laptop",
      "fixed_solution_path": "solutions/hard/CASE-H02-hql-injection-FIXED",
      "expected_hwsec_classification": "DETECTED"
    },
    {
      "case_id": "CASE-H03",
      "difficulty": "hard",
      "vulnerability_class": "CWE-611 XXE",
      "primary_entry_point": "POST /api/xml/parse",
      "source_to_sink": "@RequestBody xmlContent -> DocumentBuilderFactory.newDefaultInstance().parse(xmlContent)",
      "exploit_witness": "POST XML with DOCTYPE entity referencing file:///tmp/secret",
      "expected_security_effect": "Reads local file contents into response",
      "negative_control": "POST clean XML <foo>bar</foo>",
      "fixed_solution_path": "solutions/hard/CASE-H03-xxe-FIXED",
      "expected_hwsec_classification": "DETECTED"
    }
  ]
};

writeFile('answer_key/benchmark_manifest.json', JSON.stringify(manifest, null, 2));

// Helper for pom.xml
function getPom(artifactId, isJpa = false, isAop = false) {
    return `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
        <relativePath/>
    </parent>
    <groupId>com.hwsec</groupId>
    <artifactId>${artifactId}</artifactId>
    <version>1.0.0</version>
    <name>${artifactId}</name>
    <properties>
        <java.version>17</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-jdbc</artifactId>
        </dependency>
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>runtime</scope>
        </dependency>
        ${isJpa ? `<dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>` : ''}
        ${isAop ? `<dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-aop</artifactId>
        </dependency>` : ''}
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>`;
}

// -------------------------------------------------------------
// CASE-E01 (Command Injection)
// -------------------------------------------------------------
const e01Target = 'benchmark_targets/easy/CASE-E01-command-injection';
writeFile(`${e01Target}/pom.xml`, getPom('case-e01'));
writeFile(`${e01Target}/README.md`, '# CASE-E01 Command Injection\n\nRun with `mvn test`');
writeFile(`${e01Target}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication
public class Application {
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }
}`);
writeFile(`${e01Target}/src/main/java/com/hwsec/DiagnosticController.java`, `package com.hwsec;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/diagnostic")
public class DiagnosticController {
    @PostMapping("/ping")
    public List<String> pingHost(@RequestBody PingRequest request) {
        List<String> output = new ArrayList<>();
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping -c 1 -W 2 " + request.getHost());
            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) output.add(line);
            }
            process.waitFor();
        } catch (Exception e) { output.add("Error: " + e.getMessage()); }
        return output;
    }
    public static class PingRequest {
        private String host;
        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }
    }
}`);

// E01 Solution
const e01Sol = 'solutions/easy/CASE-E01-command-injection-FIXED';
writeFile(`${e01Sol}/pom.xml`, getPom('case-e01-fixed'));
writeFile(`${e01Sol}/FIX_NOTES.md`, '# Fix Notes CASE-E01\n\nProcessBuilder array without shell execution.');
writeFile(`${e01Sol}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication
public class Application {
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }
}`);
writeFile(`${e01Sol}/src/main/java/com/hwsec/DiagnosticController.java`, `package com.hwsec;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/diagnostic")
public class DiagnosticController {
    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9.\\\\-]+$");

    @PostMapping("/ping")
    public List<String> pingHost(@RequestBody PingRequest request) {
        List<String> output = new ArrayList<>();
        if (request.getHost() == null || !HOST_PATTERN.matcher(request.getHost()).matches()) {
            output.add("Invalid host");
            return output;
        }
        try {
            ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", "-W", "2", request.getHost());
            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) output.add(line);
            }
            process.waitFor();
        } catch (Exception e) { output.add("Error: " + e.getMessage()); }
        return output;
    }
    public static class PingRequest {
        private String host;
        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }
    }
}`);

// -------------------------------------------------------------
// CASE-E02 (SQL Injection)
// -------------------------------------------------------------
const e02Target = 'benchmark_targets/easy/CASE-E02-sql-injection';
writeFile(`${e02Target}/pom.xml`, getPom('case-e02'));
writeFile(`${e02Target}/README.md`, '# CASE-E02 SQL Injection\n\nRun with `mvn test`');
writeFile(`${e02Target}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.CommandLineRunner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@SpringBootApplication
@RestController
public class Application implements CommandLineRunner {
    @Autowired
    private JdbcTemplate jdbc;

    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @Override
    public void run(String... args) {
        jdbc.execute("CREATE TABLE users (id INT, username VARCHAR(50), role VARCHAR(50))");
        jdbc.execute("INSERT INTO users VALUES (1, 'admin', 'admin'), (2, 'alice', 'user'), (3, 'bob', 'user')");
    }

    @GetMapping("/api/users/search")
    public List<Map<String, Object>> searchUsers(@RequestParam String username) {
        String query = "SELECT id, username, role FROM users WHERE username = '" + username + "'";
        return jdbc.queryForList(query);
    }
}`);

// E02 Solution
const e02Sol = 'solutions/easy/CASE-E02-sql-injection-FIXED';
writeFile(`${e02Sol}/pom.xml`, getPom('case-e02-fixed'));
writeFile(`${e02Sol}/FIX_NOTES.md`, '# Fix Notes CASE-E02\n\nParameterized query.');
writeFile(`${e02Sol}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.CommandLineRunner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@SpringBootApplication
@RestController
public class Application implements CommandLineRunner {
    @Autowired
    private JdbcTemplate jdbc;

    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @Override
    public void run(String... args) {
        jdbc.execute("CREATE TABLE users (id INT, username VARCHAR(50), role VARCHAR(50))");
        jdbc.execute("INSERT INTO users VALUES (1, 'admin', 'admin'), (2, 'alice', 'user'), (3, 'bob', 'user')");
    }

    @GetMapping("/api/users/search")
    public List<Map<String, Object>> searchUsers(@RequestParam String username) {
        String query = "SELECT id, username, role FROM users WHERE username = ?";
        return jdbc.queryForList(query, username);
    }
}`);

// -------------------------------------------------------------
// CASE-E03 (Path Traversal)
// -------------------------------------------------------------
const e03Target = 'benchmark_targets/easy/CASE-E03-path-traversal';
writeFile(`${e03Target}/pom.xml`, getPom('case-e03'));
writeFile(`${e03Target}/README.md`, '# CASE-E03 Path Traversal');
writeFile(`${e03Target}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;

@SpringBootApplication
@RestController
public class Application {
    private static final String BASE_DIR = "/tmp/hwsec_e03_files";

    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @GetMapping("/api/files/download")
    public String downloadFile(@RequestParam String filename) throws IOException {
        Path basePath = Paths.get(BASE_DIR);
        Path filePath = basePath.resolve(filename);
        return Files.readString(filePath);
    }
}`);

const e03Sol = 'solutions/easy/CASE-E03-path-traversal-FIXED';
writeFile(`${e03Sol}/pom.xml`, getPom('case-e03-fixed'));
writeFile(`${e03Sol}/FIX_NOTES.md`, '# Fix Notes CASE-E03\n\nResolved boundary verification.');
writeFile(`${e03Sol}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;

@SpringBootApplication
@RestController
public class Application {
    private static final String BASE_DIR = "/tmp/hwsec_e03_files";

    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @GetMapping("/api/files/download")
    public String downloadFile(@RequestParam String filename) throws IOException {
        Path basePath = Paths.get(BASE_DIR).toAbsolutePath().normalize();
        Path filePath = basePath.resolve(filename).normalize();
        if (!filePath.startsWith(basePath)) {
            throw new SecurityException("Access denied");
        }
        return Files.readString(filePath);
    }
}`);

// -------------------------------------------------------------
// CASE-M01 (Stored XSS)
// -------------------------------------------------------------
const m01Target = 'benchmark_targets/medium/CASE-M01-xss-stored';
writeFile(`${m01Target}/pom.xml`, getPom('case-m01'));
writeFile(`${m01Target}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
@RestController
public class Application {
    private final ConcurrentHashMap<String, String> db = new ConcurrentHashMap<>();

    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @PostMapping("/api/messages")
    public String addMessage(@RequestBody String content) {
        String id = String.valueOf(db.size() + 1);
        db.put(id, content);
        return id;
    }

    @GetMapping("/api/messages/{id}")
    public String getMessage(@PathVariable String id) {
        String content = db.getOrDefault(id, "Not found");
        return "<div>" + content + "</div>";
    }
}`);

const m01Sol = 'solutions/medium/CASE-M01-xss-stored-FIXED';
writeFile(`${m01Sol}/pom.xml`, getPom('case-m01-fixed'));
writeFile(`${m01Sol}/FIX_NOTES.md`, '# Fix Notes CASE-M01\n\nHtmlUtils.htmlEscape');
writeFile(`${m01Sol}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
@RestController
public class Application {
    private final ConcurrentHashMap<String, String> db = new ConcurrentHashMap<>();

    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @PostMapping("/api/messages")
    public String addMessage(@RequestBody String content) {
        String id = String.valueOf(db.size() + 1);
        db.put(id, HtmlUtils.htmlEscape(content));
        return id;
    }

    @GetMapping("/api/messages/{id}")
    public String getMessage(@PathVariable String id) {
        String content = db.getOrDefault(id, "Not found");
        return "<div>" + content + "</div>";
    }
}`);

// -------------------------------------------------------------
// CASE-M02 (LDAP Injection)
// -------------------------------------------------------------
const m02Target = 'benchmark_targets/medium/CASE-M02-ldap-injection';
writeFile(`${m02Target}/pom.xml`, getPom('case-m02'));
writeFile(`${m02Target}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class Application {
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @GetMapping("/api/auth/lookup")
    public String lookupUser(@RequestParam String username) {
        String filter = "(cn=" + username + ")";
        if (filter.contains("(|(cn=*))") || filter.contains("admin")) return "User found";
        return "User not found";
    }
}`);

const m02Sol = 'solutions/medium/CASE-M02-ldap-injection-FIXED';
writeFile(`${m02Sol}/pom.xml`, getPom('case-m02-fixed'));
writeFile(`${m02Sol}/FIX_NOTES.md`, '# Fix Notes CASE-M02\n\nLDAP input encoding');
writeFile(`${m02Sol}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class Application {
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @GetMapping("/api/auth/lookup")
    public String lookupUser(@RequestParam String username) {
        String encoded = username.replaceAll("[\\\\\\\\*()\\\\u0000]", "\\\\\\\\$0");
        String filter = "(cn=" + encoded + ")";
        if (filter.contains("admin") && !username.contains("*")) return "User found";
        return "User not found";
    }
}`);

// -------------------------------------------------------------
// CASE-M03 (XPath Injection)
// -------------------------------------------------------------
const m03Target = 'benchmark_targets/medium/CASE-M03-xpath-injection';
writeFile(`${m03Target}/pom.xml`, getPom('case-m03'));
writeFile(`${m03Target}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.xml.xpath.*;
import org.w3c.dom.Document;
import javax.xml.parsers.*;
import java.io.StringReader;
import org.xml.sax.InputSource;

@SpringBootApplication
@RestController
public class Application {
    private static final String XML_DOC = "<users><user><name>admin</name><role>admin</role></user></users>";

    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @GetMapping("/api/xml/search")
    public String searchUser(@RequestParam String username) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(XML_DOC)));
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = "/users/user[name='" + username + "']/role/text()";
        return xpath.compile(expr).evaluate(doc);
    }
}`);

const m03Sol = 'solutions/medium/CASE-M03-xpath-injection-FIXED';
writeFile(`${m03Sol}/pom.xml`, getPom('case-m03-fixed'));
writeFile(`${m03Sol}/FIX_NOTES.md`, '# Fix Notes CASE-M03\n\nXPathVariableResolver');
writeFile(`${m03Sol}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.xml.xpath.*;
import org.w3c.dom.Document;
import javax.xml.parsers.*;
import java.io.StringReader;
import org.xml.sax.InputSource;

@SpringBootApplication
@RestController
public class Application {
    private static final String XML_DOC = "<users><user><name>admin</name><role>admin</role></user></users>";

    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @GetMapping("/api/xml/search")
    public String searchUser(@RequestParam String username) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(XML_DOC)));
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setXPathVariableResolver(v -> "user".equals(v.getLocalPart()) ? username : null);
        String expr = "/users/user[name=$user]/role/text()";
        return xpath.compile(expr).evaluate(doc);
    }
}`);

// -------------------------------------------------------------
// CASE-H01 (SpEL Injection)
// -------------------------------------------------------------
const h01Target = 'benchmark_targets/hard/CASE-H01-spel-injection';
writeFile(`${h01Target}/pom.xml`, getPom('case-h01', false, true));
writeFile(`${h01Target}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.expression.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

@SpringBootApplication
@RestController
public class Application {
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @PostMapping("/api/rules/evaluate")
    public String evaluateRule(@RequestBody RuleRequest request) {
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("user", "admin");
        Expression exp = parser.parseExpression(request.getExpression());
        Object val = exp.getValue(context);
        return val != null ? val.toString() : "null";
    }

    public static class RuleRequest {
        private String expression;
        public String getExpression() { return expression; }
        public void setExpression(String expression) { this.expression = expression; }
    }
}`);

const h01Sol = 'solutions/hard/CASE-H01-spel-injection-FIXED';
writeFile(`${h01Sol}/pom.xml`, getPom('case-h01-fixed', false, true));
writeFile(`${h01Sol}/FIX_NOTES.md`, '# Fix Notes CASE-H01\n\nSimpleEvaluationContext');
writeFile(`${h01Sol}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.expression.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

@SpringBootApplication
@RestController
public class Application {
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @PostMapping("/api/rules/evaluate")
    public String evaluateRule(@RequestBody RuleRequest request) {
        try {
            ExpressionParser parser = new SpelExpressionParser();
            SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
            context.setVariable("user", "admin");
            Expression exp = parser.parseExpression(request.getExpression());
            Object val = exp.getValue(context);
            return val != null ? val.toString() : "null";
        } catch (Exception e) {
            return "Execution Blocked";
        }
    }

    public static class RuleRequest {
        private String expression;
        public String getExpression() { return expression; }
        public void setExpression(String expression) { this.expression = expression; }
    }
}`);

// -------------------------------------------------------------
// CASE-H02 (HQL Injection)
// -------------------------------------------------------------
const h02Target = 'benchmark_targets/hard/CASE-H02-hql-injection';
writeFile(`${h02Target}/pom.xml`, getPom('case-h02', true));
writeFile(`${h02Target}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.CommandLineRunner;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.persistence.*;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@SpringBootApplication
@RestController
public class Application implements CommandLineRunner {
    @Autowired private EntityManager em;

    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @Override
    @Transactional
    public void run(String... args) {
        em.createNativeQuery("CREATE TABLE product (id INT PRIMARY KEY, name VARCHAR(50), price DOUBLE)").executeUpdate();
        em.createNativeQuery("INSERT INTO product VALUES (1, 'Laptop', 999.0), (2, 'Mouse', 25.0)").executeUpdate();
    }

    @GetMapping("/api/products/search")
    @Transactional
    public List<?> searchProducts(@RequestParam String name) {
        String hql = "SELECT p.name FROM Product p WHERE p.name = '" + name + "'";
        return em.createQuery(hql).getResultList();
    }
}

@Entity
@Table(name = "product")
class Product {
    @Id private Integer id;
    private String name;
    private Double price;
    public Integer getId() { return id; }
    public String getName() { return name; }
    public Double getPrice() { return price; }
}`);

const h02Sol = 'solutions/hard/CASE-H02-hql-injection-FIXED';
writeFile(`${h02Sol}/pom.xml`, getPom('case-h02-fixed', true));
writeFile(`${h02Sol}/FIX_NOTES.md`, '# Fix Notes CASE-H02\n\nNamed parameter HQL query');
writeFile(`${h02Sol}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.CommandLineRunner;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.persistence.*;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@SpringBootApplication
@RestController
public class Application implements CommandLineRunner {
    @Autowired private EntityManager em;

    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @Override
    @Transactional
    public void run(String... args) {
        em.createNativeQuery("CREATE TABLE product (id INT PRIMARY KEY, name VARCHAR(50), price DOUBLE)").executeUpdate();
        em.createNativeQuery("INSERT INTO product VALUES (1, 'Laptop', 999.0), (2, 'Mouse', 25.0)").executeUpdate();
    }

    @GetMapping("/api/products/search")
    @Transactional
    public List<?> searchProducts(@RequestParam String name) {
        String hql = "SELECT p.name FROM Product p WHERE p.name = :name";
        return em.createQuery(hql).setParameter("name", name).getResultList();
    }
}

@Entity
@Table(name = "product")
class Product {
    @Id private Integer id;
    private String name;
    private Double price;
    public Integer getId() { return id; }
    public String getName() { return name; }
    public Double getPrice() { return price; }
}`);

// -------------------------------------------------------------
// CASE-H03 (XXE)
// -------------------------------------------------------------
const h03Target = 'benchmark_targets/hard/CASE-H03-xxe';
writeFile(`${h03Target}/pom.xml`, getPom('case-h03'));
writeFile(`${h03Target}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.xml.parsers.*;
import java.io.StringReader;
import org.xml.sax.InputSource;
import org.w3c.dom.Document;

@SpringBootApplication
@RestController
public class Application {
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @PostMapping("/api/xml/parse")
    public String parseXml(@RequestBody String xmlContent) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));
        return doc.getDocumentElement().getTextContent();
    }
}`);

const h03Sol = 'solutions/hard/CASE-H03-xxe-FIXED';
writeFile(`${h03Sol}/pom.xml`, getPom('case-h03-fixed'));
writeFile(`${h03Sol}/FIX_NOTES.md`, '# Fix Notes CASE-H03\n\nDisabled DOCTYPE and external entities');
writeFile(`${h03Sol}/src/main/java/com/hwsec/Application.java`, `package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.xml.parsers.*;
import java.io.StringReader;
import org.xml.sax.InputSource;
import org.w3c.dom.Document;

@SpringBootApplication
@RestController
public class Application {
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @PostMapping("/api/xml/parse")
    public String parseXml(@RequestBody String xmlContent) throws Exception {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));
            return doc.getDocumentElement().getTextContent();
        } catch (Exception e) {
            return "XML Parsing Disabled/Error";
        }
    }
}`);

console.log('[+] Java Benchmark Generated Successfully!');
