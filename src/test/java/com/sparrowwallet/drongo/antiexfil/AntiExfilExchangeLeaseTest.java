package com.sparrowwallet.drongo.antiexfil;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class AntiExfilExchangeLeaseTest {
    @TempDir Path temporary;

    @Test void sameJvmClaimRejectsWithoutInvalidatingOwnerAndDoubleCloseIsSafe() {
        var first = AntiExfilExchangeLease.acquire(temporary);
        try {
            assertEquals(AntiExfilException.Code.ACCOUNT_EXCHANGE_BUSY,
                    assertThrows(AntiExfilException.class, () -> AntiExfilExchangeLease.acquire(temporary)).getCode());
            first.check();
        } finally { first.close(); first.close(); }
        try(var next = AntiExfilExchangeLease.acquire(temporary)) { next.check(); }
    }

    @Test void failedOsAcquireRollsBackJvmClaimAndDeathAllowsAcquisition() throws Exception {
        Process holder = startHolder();
        try {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
            while(!Files.exists(temporary.resolve("ready")) && holder.isAlive() && System.nanoTime() < deadline) Thread.sleep(10);
            assertTrue(Files.exists(temporary.resolve("ready")), "Holder failed: " + (holder.isAlive() ? "timeout" : new String(holder.getInputStream().readAllBytes())));
            for(int i = 0; i < 2; i++) assertEquals(AntiExfilException.Code.ACCOUNT_EXCHANGE_BUSY,
                    assertThrows(AntiExfilException.class, () -> AntiExfilExchangeLease.acquire(temporary)).getCode());
            holder.destroyForcibly();
            assertTrue(holder.waitFor(15, TimeUnit.SECONDS));
            try(var next = AntiExfilExchangeLease.acquire(temporary)) { next.check(); }
        } finally { if(holder.isAlive()) { holder.destroyForcibly(); holder.waitFor(15, TimeUnit.SECONDS); } }
    }

    @Test void swappedPathRefusesAndReleasesExactOwner() throws Exception {
        var first = AntiExfilExchangeLease.acquire(temporary);
        Path path = temporary.resolve("exchange.lease");
        try {
            Files.move(path, temporary.resolve("retained-original.lease"));
            Files.writeString(path, "replacement");
            assertEquals(AntiExfilException.Code.HISTORY_STORAGE_ERROR,
                    assertThrows(AntiExfilException.class, first::check).getCode());
            try(var next = AntiExfilExchangeLease.acquire(temporary)) { next.check(); }
        } finally { first.close(); }
    }

    @Test void openFailureDoesNotLeavePhantomClaim() throws Exception {
        Files.createDirectory(temporary.resolve("exchange.lease"));
        assertEquals(AntiExfilException.Code.HISTORY_STORAGE_ERROR,
                assertThrows(AntiExfilException.class, () -> AntiExfilExchangeLease.acquire(temporary)).getCode());
        Files.delete(temporary.resolve("exchange.lease"));
        try(var next = AntiExfilExchangeLease.acquire(temporary)) { next.check(); }
    }

    private Process startHolder() throws Exception {
        String tests = Path.of(AntiExfilExchangeLeaseProbe.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String main = Path.of(AntiExfilExchangeLease.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        List<String> command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED", "--add-opens=java.base/sun.nio.fs=ALL-UNNAMED",
                "--add-opens=java.base/java.io=ALL-UNNAMED", "-cp", tests + java.io.File.pathSeparator + main,
                AntiExfilExchangeLeaseProbe.class.getName(), temporary.toString(), temporary.resolve("ready").toString()));
        return new ProcessBuilder(command).redirectErrorStream(true).start();
    }
}
