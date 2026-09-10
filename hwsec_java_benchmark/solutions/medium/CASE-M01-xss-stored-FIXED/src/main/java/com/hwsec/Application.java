package com.hwsec;
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
}
