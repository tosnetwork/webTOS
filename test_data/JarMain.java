import java.io.InputStream;
import java.nio.charset.StandardCharsets;

final class JarMain {
    public static void main(String[] args) throws Exception {
        byte[] data;
        try (InputStream in = JarMain.class.getResourceAsStream("/payload.txt")) {
            if (in == null) {
                throw new IllegalStateException("missing payload resource");
            }
            data = in.readAllBytes();
        }

        String payload = new String(data, StandardCharsets.UTF_8).trim();
        System.out.println("ATOS-JAVA-JAR payload=" + payload);
    }
}
