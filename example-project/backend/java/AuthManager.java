import java.io.*;

public class AuthManager {
    public Object deserializeToken(InputStream inStream) throws Exception {
        // Deliberate CWE-502: Unsafe Java Deserialization
        ObjectInputStream ois = new ObjectInputStream(inStream);
        return ois.readObject();
    }
}
