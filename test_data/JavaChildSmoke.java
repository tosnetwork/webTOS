import java.io.BufferedReader;
import java.io.InputStreamReader;

final class JavaChildSmoke {
    public static void main(String[] args) throws Exception {
        System.out.println("ATOS-JAVA-CHILD stage=start");
        Process child = new ProcessBuilder(
                "/usr/lib/jvm/java-11-openjdk-amd64/bin/java",
                "-Xshare:off",
                "-XX:-UsePerfData",
                "-cp",
                "/usr/lib/atos-tests",
                "Hello")
                .redirectErrorStream(true)
                .start();
        System.out.println("ATOS-JAVA-CHILD stage=started");

        String firstLine;
        try (BufferedReader reader =
                     new BufferedReader(new InputStreamReader(child.getInputStream()))) {
            firstLine = reader.readLine();
            System.out.println(
                    "ATOS-JAVA-CHILD stage=readline first="
                            + (firstLine == null ? "<missing>" : firstLine));
            while (reader.readLine() != null) {
                // Drain the stream so waitFor() observes normal EOF.
            }
            System.out.println("ATOS-JAVA-CHILD stage=drained");
        }

        System.out.println("ATOS-JAVA-CHILD stage=wait");
        int status = child.waitFor();
        if (firstLine == null) {
            firstLine = "<missing>";
        }

        System.out.println("ATOS-JAVA-CHILD line=" + firstLine + " status=" + status);
        if (status != 0) {
            System.exit(1);
        }
    }
}
