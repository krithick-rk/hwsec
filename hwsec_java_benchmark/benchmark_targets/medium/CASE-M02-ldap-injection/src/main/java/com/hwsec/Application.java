package com.hwsec;
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
}
