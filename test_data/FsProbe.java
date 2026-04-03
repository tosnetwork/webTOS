import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

final class FsProbe {
    public static void main(String[] args) throws Exception {
        Path testsRoot = Path.of(System.getProperty("tos.tests.root", "/usr/lib/tos-tests"));
        int count = 0;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(testsRoot)) {
            for (Path ignored : stream) {
                count++;
            }
        }

        byte[] sample = Files.readAllBytes(testsRoot.resolve("payload.txt"));
        String firstLine = new String(sample, StandardCharsets.UTF_8).split("\n", 2)[0];
        Path tempRoot = Path.of("/tmp", "tos-java-fs-" + ProcessHandle.current().pid());
        Path tempFile = tempRoot.resolve("roundtrip.txt");

        Files.createDirectories(tempRoot);
        Files.writeString(tempFile, "roundtrip\n", StandardCharsets.UTF_8);
        Path movedFile = Files.move(tempFile, tempRoot.resolve("moved.txt"));
        String roundtrip = Files.readString(movedFile, StandardCharsets.UTF_8);
        long tempCount;
        try (Stream<Path> stream = Files.list(tempRoot)) {
            tempCount = stream.count();
        }
        long tempBytes = Files.size(movedFile);
        Files.delete(movedFile);
        Files.delete(tempRoot);

        if (tempCount != 1 || tempBytes != roundtrip.length() || !roundtrip.equals("roundtrip\n")) {
            throw new IllegalStateException(
                    "temp fs mismatch count=" + tempCount + " bytes=" + tempBytes + " data=" + roundtrip);
        }

        System.out.println("TOS-JAVA-FS count=" + count);
        System.out.println("TOS-JAVA-FS first=" + firstLine);
        System.out.println("TOS-JAVA-FS-TMP-OK entries=" + tempCount + " bytes=" + tempBytes);
    }
}
