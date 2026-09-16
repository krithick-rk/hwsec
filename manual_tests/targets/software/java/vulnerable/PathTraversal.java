import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class PathTraversal {
    public static void readFile(String userPath) throws IOException {
        // Unsanitized file path construction
        File f = new File("/var/app/data/" + userPath);
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
