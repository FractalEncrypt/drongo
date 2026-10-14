package com.sparrowwallet.drongo.antiexfil;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;
/** Process-lock test helper retained from the historical durable lifecycle suite. */
class AntiExfilAbortStateMachineTest {
    public static final class LockHolder implements AutoCloseable {
        private final Process process;
        private final BufferedReader output;
        private boolean closed;

        private LockHolder(Process process) {
            this.process = process;
            this.output = process.inputReader(StandardCharsets.UTF_8);
        }

        static LockHolder acquire(Path lockPath) throws IOException {
            String java = Path.of(System.getProperty("java.home"), "bin", isWindows() ? "java.exe" : "java").toString();
            Process process = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                    LockHolder.class.getName(), lockPath.toString()).redirectErrorStream(true).start();
            LockHolder holder = new LockHolder(process);
            assertEquals("LOCKED", holder.output.readLine());
            return holder;
        }

        void awaitContender() throws InterruptedException {
            Thread.sleep(250);
        }

        @Override
        public void close() throws IOException, InterruptedException {
            if(closed) return;
            closed = true;
            process.getOutputStream().close();
            assertTrue(process.waitFor(5, TimeUnit.SECONDS));
            assertEquals(0, process.exitValue());
        }

        public static void main(String[] args) throws Exception {
            Path lockPath = Path.of(args[0]);
            Files.createDirectories(lockPath.toAbsolutePath().getParent());
            try(FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                FileLock ignored = channel.lock()) {
                System.out.println("LOCKED");
                System.out.flush();
                System.in.readAllBytes();
            }
        }

        private static boolean isWindows() {
            return System.getProperty("os.name").toLowerCase().contains("win");
        }
    }
}
