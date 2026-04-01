import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;

final class FsProbe {
    public static void main(String[] args) throws Exception {
        int count = 0;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(Path.of("/usr/lib/tos-tests"))) {
            for (Path ignored : stream) {
                count++;
            }
        }

        byte[] sample = Files.readAllBytes(Path.of("/usr/lib/tos-tests/payload.txt"));
        String firstLine = new String(sample, StandardCharsets.UTF_8).split("\n", 2)[0];

        System.out.println("TOS-JAVA-FS count=" + count);
        System.out.println("TOS-JAVA-FS first=" + firstLine);
    }
}
