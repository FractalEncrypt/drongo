package com.sparrowwallet.drongo.antiexfil;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class AntiExfilDurableFilesConcurrencyTest {
    @TempDir
    Path temporary;

    @Test
    void serializesCriticalSectionAcrossThreads() throws Exception {
        Path target = temporary.resolve("thread-session.aexs");
        CountDownLatch ready = new CountDownLatch(16);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maximumActive = new AtomicInteger();
        try(var executor = Executors.newFixedThreadPool(16)) {
            List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
            for(int i = 0; i < 16; i++) {
                futures.add(executor.submit(() -> {
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    AntiExfilDurableFiles.locked(target, () -> {
                        int entered = active.incrementAndGet();
                        maximumActive.accumulateAndGet(entered, Math::max);
                        try {
                            Thread.sleep(10);
                        } catch(InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new java.io.IOException("Interrupted in lock probe", e);
                        } finally {
                            active.decrementAndGet();
                        }
                        return null;
                    });
                    return null;
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            for(var future : futures) future.get(10, TimeUnit.SECONDS);
        }
        assertEquals(1, maximumActive.get());
        assertEquals(0, active.get());
    }

    @Test
    void serializesCriticalSectionAcrossIndependentJvmProcesses() throws Exception {
        Path target = temporary.resolve("process-session.aexs");
        Path control = temporary.resolve("control");
        Files.createDirectory(control);

        Process holder = startProbe(target, control, "holder", true);
        awaitFile(control.resolve("acquired-holder"));
        Process contender = startProbe(target, control, "contender", false);

        Thread.sleep(300);
        assertFalse(Files.exists(control.resolve("acquired-contender")),
                "Independent contender entered while holder still owned the OS lock");
        Files.writeString(control.resolve("release-holder"), "release");

        assertTrue(holder.waitFor(10, TimeUnit.SECONDS));
        assertTrue(contender.waitFor(10, TimeUnit.SECONDS));
        assertEquals(0, holder.exitValue(), processOutput(holder));
        assertEquals(0, contender.exitValue(), processOutput(contender));
        assertTrue(Files.exists(control.resolve("acquired-contender")));
        try(var markers = Files.list(control)) {
            assertFalse(markers.anyMatch(path -> path.getFileName().toString().startsWith("inside-")));
        }
    }

    private Process startProbe(Path target, Path control, String identity, boolean hold) throws Exception {
        String javaExecutable = Path.of(System.getProperty("java.home"), "bin", isWindows() ? "java.exe" : "java").toString();
        String testClasses = Path.of(AntiExfilLockProcessProbe.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).toString();
        String mainClasses = Path.of(AntiExfilDurableFiles.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).toString();
        return new ProcessBuilder(javaExecutable, "-cp", testClasses + java.io.File.pathSeparator + mainClasses,
                AntiExfilLockProcessProbe.class.getName(), target.toString(), control.toString(), identity,
                Boolean.toString(hold))
                .redirectErrorStream(true)
                .start();
    }

    private static void awaitFile(Path marker) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while(!Files.exists(marker) && System.nanoTime() < deadline) Thread.sleep(10);
        assertTrue(Files.exists(marker), "Timed out waiting for " + marker);
    }

    private static String processOutput(Process process) throws Exception {
        return new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT).contains("win");
    }
}
