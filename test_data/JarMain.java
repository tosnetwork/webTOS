import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

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
        int entries = 0;
        boolean sawPayload = false;
        try (InputStream raw = JarMain.class.getProtectionDomain().getCodeSource().getLocation().openStream();
             JarInputStream jar = new JarInputStream(raw)) {
            JarEntry entry;
            while ((entry = jar.getNextJarEntry()) != null) {
                entries++;
                if ("payload.txt".equals(entry.getName())) {
                    sawPayload = true;
                }
            }
        }

        if (!sawPayload || entries == 0) {
            throw new IllegalStateException("jar payload scan failed entries=" + entries);
        }

        System.out.println("TOS-JAVA-JAR payload=" + payload);
        System.out.println("TOS-JAVA-ZIP-OK entries=" + entries);
    }
}
