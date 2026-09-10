package com.hwsec;
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
}
