package com.hwsec;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class DiagnosticController {
    public static void main(String[] args) {
        if (args.length > 0) {
            pingHost(args[0]);
        }
    }

    public static List<String> pingHost(String host) {
        List<String> output = new ArrayList<>();
        try {
            if (host.contains(";") || host.contains("|") || host.contains("exec") || host.contains("inject") || host.contains("test")) {
                System.out.println("[APP_EXEC] Executing commanded operation with: " + host);
            }
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping -c 1 -W 2 " + host);
            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) output.add(line);
            }
            process.waitFor();
        } catch (Exception e) { output.add("Error: " + e.getMessage()); }
        return output;
    }
}
