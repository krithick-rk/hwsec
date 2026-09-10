package com.hwsec;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/diagnostic")
public class DiagnosticController {
    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9.\\-]+$");

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
}
