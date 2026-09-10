package com.hwsec;
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
}
