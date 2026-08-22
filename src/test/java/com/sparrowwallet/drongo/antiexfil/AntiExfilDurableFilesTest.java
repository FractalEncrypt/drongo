package com.sparrowwallet.drongo.antiexfil;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

class AntiExfilDurableFilesTest {
    @TempDir
    Path temporary;

    @Test
    void directoryBarrierRunsAfterAtomicReplacementBeforeReturn() throws Exception {
        Path state = temporary.resolve("ordered.aexs");
        byte[] body = {1, 2, 3, 4};
        AtomicBoolean barrier = new AtomicBoolean();

        AntiExfilDurableFiles.write(state, body, true, 128, parent -> {
            assertEquals(temporary.toRealPath(), parent.toRealPath());
            assertArrayEquals(body, AntiExfilDurableFiles.read(state, 128));
            barrier.set(true);
        });

        assertTrue(barrier.get());
    }

    @Test
    void failedDirectoryBarrierCannotLeaveAReadableUncommittedState() {
        Path state = temporary.resolve("barrier-failed.aexs");
        assertThrows(IOException.class, () -> AntiExfilDurableFiles.write(
                state, new byte[]{1, 2, 3}, true, 128,
                parent -> { throw new IOException("injected directory-force failure"); }));
        assertThrows(IOException.class, () -> AntiExfilDurableFiles.read(state, 128));
    }

    @Test
    void boundedReadRejectsSparseOversizeBeforeAllocation() throws Exception {
        Path state = temporary.resolve("oversized.aexs");
        try(FileChannel channel = FileChannel.open(state, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            channel.position(128);
            channel.write(ByteBuffer.wrap(new byte[]{1}));
        }

        IOException rejected = assertThrows(IOException.class,
                () -> AntiExfilDurableFiles.read(state, 128));
        assertTrue(rejected.getMessage().contains("outside limits"));
    }

    @Test
    void writeAndReadUseTheSameExactFileCap() throws Exception {
        Path exact = temporary.resolve("exact.aexs");
        byte[] exactBody = new byte[96];
        AntiExfilDurableFiles.write(exact, exactBody, true, 128);
        assertArrayEquals(exactBody, AntiExfilDurableFiles.read(exact, 128));

        Path over = temporary.resolve("over.aexs");
        assertThrows(IOException.class,
                () -> AntiExfilDurableFiles.write(over, new byte[97], true, 128));
        assertFalse(Files.exists(over));
    }

    @Test
    void overLimitReplacementPreservesPriorValidState() throws Exception {
        Path state = temporary.resolve("preserved.aexs");
        byte[] original = {9, 8, 7};
        AntiExfilDurableFiles.write(state, original, true, 128);

        assertThrows(IOException.class,
                () -> AntiExfilDurableFiles.write(state, new byte[97], false, 128));
        assertArrayEquals(original, AntiExfilDurableFiles.read(state, 128));
    }

    @Test
    void hardLinkAliasesSerializeAndDetachedAliasCannotRetainValidState() throws Exception {
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            Path state = temporary.resolve("state.aexs");
            Path alias = temporary.resolve("alias.aexs");
            AntiExfilDurableFiles.write(state, new byte[]{1}, true, 128);
            try {
                Files.createLink(alias, state);
            } catch(UnsupportedOperationException | IOException | SecurityException e) {
                org.junit.jupiter.api.Assumptions.assumeTrue(false,
                        "hard links are unavailable: " + e.getMessage());
            }

            CountDownLatch firstEntered = new CountDownLatch(1);
            CountDownLatch releaseFirst = new CountDownLatch(1);
            AtomicBoolean aliasEntered = new AtomicBoolean();
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Future<Void> first = executor.submit(() -> AntiExfilDurableFiles.locked(state, () -> {
                    firstEntered.countDown();
                    try {
                        if(!releaseFirst.await(5, TimeUnit.SECONDS)) throw new IOException("timed out");
                    } catch(InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("interrupted", e);
                    }
                    AntiExfilDurableFiles.write(state, new byte[]{2}, false, 128);
                    return null;
                }));
                assertTrue(firstEntered.await(5, TimeUnit.SECONDS));
                Future<Void> second = executor.submit(() -> AntiExfilDurableFiles.locked(alias, () -> {
                    aliasEntered.set(true);
                    return null;
                }));

                Thread.sleep(150);
                assertFalse(aliasEntered.get(), "a hard-link alias must not enter a parallel state operation");
                releaseFirst.countDown();
                first.get(5, TimeUnit.SECONDS);
                second.get(5, TimeUnit.SECONDS);
            } finally {
                releaseFirst.countDown();
                executor.shutdownNow();
            }

            assertArrayEquals(new byte[]{2}, AntiExfilDurableFiles.read(state, 128));
            assertThrows(IOException.class, () -> AntiExfilDurableFiles.read(alias, 128),
                    "the detached hard link must not retain a valid stale security state");
        });
    }

    @Test
    void posixHardLinkAliasesShareTheCrossProcessFileLock() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeFalse(isWindows(),
                "Windows cannot atomically replace a target while its FileChannel lock is held");
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            Path state = temporary.resolve("process-state.aexs");
            Path alias = temporary.resolve("process-alias.aexs");
            AntiExfilDurableFiles.write(state, new byte[]{1}, true, 128);
            try {
                Files.createLink(alias, state);
            } catch(UnsupportedOperationException | IOException | SecurityException e) {
                org.junit.jupiter.api.Assumptions.assumeTrue(false,
                        "hard links are unavailable: " + e.getMessage());
            }

            AtomicBoolean entered = new AtomicBoolean();
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try(AntiExfilAbortStateMachineTest.LockHolder holder =
                        AntiExfilAbortStateMachineTest.LockHolder.acquire(state)) {
                Future<Void> contender = executor.submit(() -> AntiExfilDurableFiles.locked(alias, () -> {
                    entered.set(true);
                    return null;
                }));
                holder.awaitContender();
                assertFalse(entered.get(), "the hard-link alias must wait for the underlying-file lock");
                holder.close();
                contender.get(5, TimeUnit.SECONDS);
                assertTrue(entered.get());
            } finally {
                executor.shutdownNow();
            }
        });
    }

    @Test
    void coordinatorStateLengthChecksExactAggregateAndPerFieldBounds() throws Exception {
        assertEquals(207, AntiExfilCoordinator.checkedStateFileLength(
                1, 1, 1, 1, 1, 1, 32, 1, 207));
        assertThrows(IOException.class, () -> AntiExfilCoordinator.checkedStateFileLength(
                1, 1, 1, 1, 1, 1, 32, 1, 206));
        assertThrows(IOException.class, () -> AntiExfilCoordinator.checkedStateFileLength(
                1, 1, -1, -1, -1, (16 * 1024 * 1024) + 1, 32, 1, Integer.MAX_VALUE));
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("windows");
    }
}
