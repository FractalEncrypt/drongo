package com.sparrowwallet.drongo.antiexfil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

public final class AntiExfilLockProcessProbe {
    private AntiExfilLockProcessProbe() {
    }

    public static void main(String[] arguments) {
        if(arguments.length != 4) throw new IllegalArgumentException("target control identity hold required");
        Path target = Path.of(arguments[0]);
        Path control = Path.of(arguments[1]);
        String identity = arguments[2];
        boolean hold = Boolean.parseBoolean(arguments[3]);
        AntiExfilDurableFiles.locked(target, () -> {
            Path inside = control.resolve("inside-" + identity);
            try(var markers = Files.list(control)) {
                if(markers.anyMatch(path -> path.getFileName().toString().startsWith("inside-"))) {
                    throw new IOException("Observed overlapping critical sections");
                }
            }
            Files.writeString(inside, identity);
            try {
                Files.writeString(control.resolve("acquired-" + identity), identity);
                if(hold) awaitRelease(control.resolve("release-" + identity));
            } finally {
                Files.deleteIfExists(inside);
            }
            return null;
        });
    }

    private static void awaitRelease(Path marker) throws IOException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while(!Files.exists(marker) && System.nanoTime() < deadline) {
            try {
                Thread.sleep(10);
            } catch(InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while awaiting process-lock release", e);
            }
        }
        if(!Files.exists(marker)) throw new IOException("Timed out awaiting process-lock release");
    }
}
