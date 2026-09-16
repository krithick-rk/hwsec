import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class PathTraversalFixed {
    public static void readFile(String userPath) throws IOException {
        Path baseDir = Paths.get("/var/app/data").toAbsolutePath().normalize();
        Path resolved = baseDir.resolve(userPath).toAbsolutePath().normalize();

        if (!resolved.startsWith(baseDir)) {
            throw new SecurityException("Path traversal attempt detected!");
        }

        File f = resolved.toFile();
        FileInputStream fis = new FileInputStream(f);
        byte[] data = fis.readAllBytes();
        System.out.println("Read " + data.length + " bytes");
        fis.close();
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            readFile(args[0]);
        }
    }
}
