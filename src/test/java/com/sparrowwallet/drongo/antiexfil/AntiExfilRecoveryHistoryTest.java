package com.sparrowwallet.drongo.antiexfil;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.*;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class AntiExfilRecoveryHistoryTest {
    @TempDir Path directory;
    private static final byte[] ACCOUNT = new byte[32];
    private static String hex(long value) { return String.format("%064x", value); }
    private static AntiExfilRecoveryHistory.Context context(long session) {
        return new AntiExfilRecoveryHistory.Context(hex(session), hex(123), hex(456), 4);
    }
    private AntiExfilRecoveryHistory history(AntiExfilExchangeLease lease) { return new AntiExfilRecoveryHistory(directory, ACCOUNT, lease); }

    @Test void t01OldUncertaintyDoesNotPreventNewSessionCompletionOrEraseCounts() {
        try(var lease = AntiExfilExchangeLease.acquire(directory)) {
            var history = history(lease);
            for(int i = 1; i <= 2; i++) {
                history.start(context(i), history.needsApproval()); history.reveal(context(i));
                history.end(context(i), "USER_ABANDONED", false);
            }
            history.start(context(3), true); history.reveal(context(3)); history.complete(context(3));
            history.refresh();
            assertEquals(new AntiExfilRecoveryHistory.Counts(3, 3, 1, 2, 0, false), history.counts());
            assertEquals(2, history.paymentUncertain(hex(456)));
            assertTrue(history.needsApproval());
        }
    }
    @Test void t02ContextStageEndedAndReusedSessionAreRefused() {
        try(var lease = AntiExfilExchangeLease.acquire(directory)) {
            var h = history(lease); var c = context(1);
            assertThrows(AntiExfilException.class, () -> h.complete(c));
            h.start(c, false);
            assertThrows(AntiExfilException.class, () -> h.complete(c));
            h.reveal(c);
            assertThrows(AntiExfilException.class, () -> h.complete(new AntiExfilRecoveryHistory.Context(c.session(), hex(999), c.payment(), 4)));
            h.end(c, "USER_ABANDONED", false);
            assertThrows(AntiExfilException.class, () -> h.complete(c));
            assertThrows(AntiExfilException.class, () -> h.start(c, true));
        }
    }
    @Test void t04ReacquisitionClassifiesUnfinishedFullColdStream() {
        try(var lease = AntiExfilExchangeLease.acquire(directory)) {
            var h = history(lease); h.start(context(1), false); h.reveal(context(1));
        }
        try(var lease = AntiExfilExchangeLease.acquire(directory)) {
            var h = history(lease); h.reconcile(); h.reconcile();
            assertEquals(1, h.counts().uncertain());
            assertEquals(1L, h.reasonCounts().get("OWNER_LOST_UNVERIFIED"));
            h.start(context(2), true); h.reveal(context(2)); h.complete(context(2));
            assertEquals(1, h.counts().completions());
        }
    }
    @Test void t08V2IsPreservedAndOldSessionIdsCannotBeReused() throws Exception {
        Path v2 = directory.resolve("old.aexj");
        var old = new AntiExfilAbortJournal(v2, ACCOUNT);
        byte[] sid = com.sparrowwallet.drongo.Utils.hexToBytes(hex(1));
        old.append(sid, new byte[32], "PENDING_REVEAL"); old.append(sid, new byte[32], "USER_ABANDONED");
        byte[] before = Files.readAllBytes(v2);
        try(var lease = AntiExfilExchangeLease.acquire(directory)) {
            var h = history(lease);
            h.importLegacy(List.of(new AntiExfilRecoveryHistory.Legacy(v2, ACCOUNT)), true);
            assertArrayEquals(before, Files.readAllBytes(v2));
            assertEquals(1, h.counts().uncertain()); assertEquals(0, h.paymentUncertain(hex(456)));
            assertTrue(h.counts().unknown()); assertTrue(h.hasSession(hex(1)));
            assertThrows(AntiExfilException.class, () -> h.start(context(1), true));
            h.refresh(); assertEquals(1, h.counts().uncertain());
        }
    }
    @Test void t09NoTenThousandEventBudgetAndHotViewStaysBounded() throws Exception {
        try(var lease = AntiExfilExchangeLease.acquire(directory)) {
            var h = history(lease);
            // Prepare a public, nonsecret synthetic cold audit with the real frame
            // encoder/durable writer; replay validates all transitions and SID uniqueness.
            var encode = AntiExfilRecoveryHistory.class.getDeclaredMethod("encode", AntiExfilRecoveryHistory.Frame.class);
            encode.setAccessible(true);
            String predecessor = "0".repeat(64); long seq = 0;
            for(int i = 1; i <= 3335; i++) for(var type : List.of(AntiExfilRecoveryHistory.Type.SESSION_STARTED,
                    AntiExfilRecoveryHistory.Type.REVEAL_MAY_HAVE_ESCAPED, AntiExfilRecoveryHistory.Type.VERIFIED_COMPLETE)) {
                var frame = new AntiExfilRecoveryHistory.Frame(++seq, predecessor, type, context(i), 1, "", "", -1, "0".repeat(64), "0".repeat(64));
                byte[] body = (byte[])encode.invoke(h, frame);
                AntiExfilDurableFiles.write(directory.resolve(String.format("%020d.aex3", seq)), body, true, 4096);
                predecessor = com.sparrowwallet.drongo.Utils.bytesToHex(com.sparrowwallet.drongo.protocol.Sha256Hash.hash(body));
            }
            h.refresh();
            assertEquals(3335, h.counts().completions()); assertEquals(128, h.hotDetailSize());
            h.start(context(4000), false); h.end(context(4000), "USER_ABANDONED", false);
        }
    }
    @Test void t10FailedRevealBarrierReturnsNoSuccessAndKeepsPriorPrefix() throws Exception {
        try(var lease = AntiExfilExchangeLease.acquire(directory)) {
            var good = history(lease); good.start(context(1), false);
            Path first = directory.resolve("00000000000000000001.aex3"); byte[] prefix = Files.readAllBytes(first);
            var failing = new AntiExfilRecoveryHistory(directory, ACCOUNT, lease,
                    (path, body) -> AntiExfilDurableFiles.write(path, body, true, 4096, parent -> { throw new IOException("barrier probe"); }));
            assertEquals(AntiExfilException.Code.HISTORY_STORAGE_ERROR,
                    assertThrows(AntiExfilException.class, () -> failing.reveal(context(1))).getCode());
            assertArrayEquals(prefix, Files.readAllBytes(first));
            assertEquals(AntiExfilException.Code.HISTORY_STORAGE_ERROR,
                    assertThrows(AntiExfilException.class, () -> history(lease)).getCode());
        }
    }
    @Test void t10CorruptOrGappedTailIsPreservedAndDiagnosed() throws Exception {
        try(var lease = AntiExfilExchangeLease.acquire(directory)) {
            var h = history(lease); h.start(context(1), false); h.end(context(1), "USER_ABANDONED", false);
            Path second = directory.resolve("00000000000000000002.aex3"); byte[] before = Files.readAllBytes(second);
            Files.move(second, directory.resolve("00000000000000000003.aex3"));
            assertThrows(AntiExfilException.class, h::refresh);
            assertArrayEquals(before, Files.readAllBytes(directory.resolve("00000000000000000003.aex3")));
        }
    }
    @Test void t12MissingOrMutatedV2IsVersionConflict() {
        Path old = directory.resolve("old.aexj");
        try(var lease = AntiExfilExchangeLease.acquire(directory)) {
            var h = history(lease); h.importLegacy(List.of(new AntiExfilRecoveryHistory.Legacy(old, ACCOUNT)), false);
            new AntiExfilAbortJournal(old, ACCOUNT).append(new byte[32], new byte[32], "USER_ABANDONED");
            assertEquals(AntiExfilException.Code.VERSION_CONFLICT, assertThrows(AntiExfilException.class, h::beforeDisclosure).getCode());
        }
    }
    @Test void t08ManyOriginsHaveNoSourceBudgetAndDuplicateLegacySessionsCountOnce() {
        var sources = new java.util.ArrayList<AntiExfilRecoveryHistory.Legacy>();
        for(int i = 0; i < 10; i++) {
            Path source = directory.resolve("origin-" + i + ".aexj");
            new AntiExfilAbortJournal(source, ACCOUNT).append(new byte[32], new byte[32], "USER_ABANDONED");
            sources.add(new AntiExfilRecoveryHistory.Legacy(source, ACCOUNT));
        }
        try(var lease = AntiExfilExchangeLease.acquire(directory)) {
            var h = history(lease); h.importLegacy(sources, false); h.refresh();
            assertEquals(1, h.counts().starts()); assertEquals(1, h.counts().uncertain());
            assertEquals(1L, h.reasonCounts().get("USER_ABANDONED"));
            h.start(context(1), true); h.reveal(context(1)); h.complete(context(1));
            h.refresh(); assertEquals(1, h.counts().completions()); assertEquals(1, h.counts().uncertain());
        }
    }
}
