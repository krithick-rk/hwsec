package com.hwsec;
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
}
