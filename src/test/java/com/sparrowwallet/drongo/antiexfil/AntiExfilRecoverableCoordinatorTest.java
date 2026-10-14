package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.wallet.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic public test keys only. This is a host implementation test, not a
 * firmware/native signer or physical-device qualification. */
class AntiExfilRecoverableCoordinatorTest {
    @TempDir Path temporary;
    byte[] raw;
    Keystore signer;
    @BeforeEach void setup() throws Exception {
        try(var in = getClass().getResourceAsStream("protocol-v1-semantic-psbt-vector.json")) {
            String vector = new String(Objects.requireNonNull(in).readAllBytes(), StandardCharsets.UTF_8);
            var matcher = Pattern.compile("\"psbt_hex\"\\s*:\\s*\"([0-9a-f]+)\"").matcher(vector);
            assertTrue(matcher.find()); raw = Utils.hexToBytes(matcher.group(1));
        }
        signer = Keystore.fromSeed(new DeterministicSeed("model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast", "", 0,
                DeterministicSeed.Type.BIP39), PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
        signer.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
    }
    private AntiExfilCoordinator.PreparedAttempt prepare() { return prepare(raw); }
    private AntiExfilCoordinator.PreparedAttempt prepare(byte[] psbt) {
        return AntiExfilCoordinator.prepare(temporary.resolve("v3"), temporary.resolve("ram.aexj"),
                temporary.resolve("origin.aexj"), false, psbt, signer, AntiExfilNetwork.TESTNET4);
    }
    private AntiExfilCoordinator start() {
        try(var attempt = prepare()) { return attempt.start(attempt.summary().requiresConfirmation() ? attempt.approve() : null); }
    }
    private byte[] openings(AntiExfilCoordinator coordinator) {
        var m1 = AntiExfilCodec.decode(coordinator.getHostCommitMessage());
        List<AntiExfilSlot> slots = new ArrayList<>();
        for(int i = 0; i < m1.getSlots().size(); i++) {
            var slot = m1.getSlots().get(i);
            slots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(), slot.getMessageHash(),
                    slot.getCommitment(), ECKey.fromPrivate(BigInteger.valueOf(1000 + i)).getPubKey(), null, null));
        }
        return AntiExfilCodec.encode(new AntiExfilMessage(m1.getNetwork(), AntiExfilStage.SIGNER_OPENINGS, m1.getSessionId(), m1.getPsbtDigest(), slots));
    }
    private byte[] sign(byte[] reveal) throws Exception {
        var m3 = AntiExfilCodec.decode(reveal);
        var semantic = AntiExfilPsbt.enumerateSigningSlots(raw, signer);
        List<AntiExfilSlot> slots = new ArrayList<>();
        BigInteger n = ECKey.CURVE.getN();
        for(int i = 0; i < m3.getSlots().size(); i++) {
            var slot = m3.getSlots().get(i);
            var key = signer.getExtendedMasterPrivateKey().getKey(semantic.get(i).getKeyDerivation().getDerivation());
            assertArrayEquals(slot.getSignerPublicKey(), key.getPubKey());
            BigInteger tweak = new BigInteger(1, Utils.taggedHash("s2c/ecdsa/point", Utils.concat(slot.getOpening(), slot.getHostRandomness())));
            BigInteger nonce = BigInteger.valueOf(1000 + i).add(tweak).mod(n);
            BigInteger r = ECKey.CURVE.getG().multiply(nonce).normalize().getAffineXCoord().toBigInteger().mod(n);
            BigInteger s = nonce.modInverse(n).multiply(new BigInteger(1, slot.getMessageHash()).add(r.multiply(key.getPrivKey()))).mod(n);
            if(s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) s = n.subtract(s);
            byte[] compact = Utils.concat(scalar(r), scalar(s));
            slots.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(), slot.getMessageHash(),
                    slot.getCommitment(), slot.getOpening(), null, compact));
        }
        return AntiExfilCodec.encode(new AntiExfilMessage(m3.getNetwork(), AntiExfilStage.SIGNER_SIGNATURES, m3.getSessionId(), m3.getPsbtDigest(), slots));
    }
    private static byte[] scalar(BigInteger value) {
        byte[] raw = value.toByteArray(), bytes = new byte[32];
        System.arraycopy(raw, Math.max(0, raw.length - 32), bytes, Math.max(0, 32 - raw.length), Math.min(32, raw.length)); return bytes;
    }
    @Test void t06EndThenSamePaymentFreshCeremonyCompletesAndKeepsHistory() throws Exception {
        byte[] oldCommit, oldOpenings, oldReveal;
        try(var c = start()) {
            oldCommit = c.getHostCommitMessage(); oldOpenings = openings(c); oldReveal = c.acceptOpenings(oldOpenings);
            assertArrayEquals(oldReveal, c.getHostRevealMessage()); assertArrayEquals(oldReveal, c.acceptOpenings(oldOpenings));
            c.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.USER_ABANDONED);
        }
        try(var attempt = prepare()) {
            assertTrue(attempt.summary().requiresConfirmation()); assertEquals(1, attempt.summary().unfinishedAfterReveal());
            assertEquals(1, attempt.summary().thisPaymentUnfinished());
            try(var c = attempt.start(attempt.approve())) {
                var commit = AntiExfilCodec.decode(c.getHostCommitMessage());
                assertFalse(Arrays.equals(oldCommit, c.getHostCommitMessage()));
                assertFalse(Arrays.equals(AntiExfilCodec.decode(oldCommit).getSessionId(), commit.getSessionId()));
                var freshReveal = c.acceptOpenings(openings(c));
                assertFalse(Arrays.equals(AntiExfilCodec.decode(oldReveal).getSlots().getFirst().getHostRandomness(), AntiExfilCodec.decode(freshReveal).getSlots().getFirst().getHostRandomness()));
                var result = c.complete(sign(freshReveal)); assertFalse(result.isBroadcast()); assertEquals(5, result.getVerifiedSignatures().size());
            }
        }
        try(var next = prepare()) { assertEquals(1, next.summary().completions()); assertEquals(1, next.summary().unfinishedAfterReveal()); }
    }
    @Test void t06OldM2AndM4AreRefusedByNewSessionAndLeaseReleased() throws Exception {
        byte[] oldM2, oldM4;
        try(var c = start()) { oldM2 = openings(c); oldM4 = sign(c.acceptOpenings(oldM2)); c.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.USER_ABANDONED); }
        try(var c = start()) { assertThrows(AntiExfilException.class, () -> c.acceptOpenings(oldM2)); }
        try(var c = start()) { c.acceptOpenings(openings(c)); assertThrows(AntiExfilException.class, () -> c.complete(oldM4)); }
        try(var attempt = prepare()) { assertTrue(attempt.summary().requiresConfirmation()); }
    }
    @Test void t05PreRevealCloseAndFailedStartReleaseOwnership() {
        try(var c = start()) { c.close(); c.close(); }
        try(var attempt = prepare()) { assertFalse(attempt.summary().requiresConfirmation()); }
        try(var c = start()) { c.acceptOpenings(openings(c)); }
        try(var attempt = prepare()) { assertThrows(AntiExfilException.class, () -> attempt.start(null)); }
        try(var attempt = prepare()) { assertEquals(1, attempt.summary().unfinishedAfterReveal()); }
    }
    @Test void t07ChangedMetadataAndFeeStillRequireAccountConfirmation() {
        try(var c = start()) { c.acceptOpenings(openings(c)); }
        var psbt = AntiExfilPsbt.parseCanonicalV0(raw);
        var transaction = psbt.getTransaction();
        var output = transaction.getOutputs().getFirst();
        byte[] encoded = psbt.serialize(), unsigned = transaction.bitcoinSerialize();
        int amountOffset = uniqueOffset(encoded, unsigned) + uniqueOffset(unsigned, output.bitcoinSerialize());
        java.nio.ByteBuffer.wrap(encoded, amountOffset, 8).order(java.nio.ByteOrder.LITTLE_ENDIAN).putLong(output.getValue() - 1);
        try(var attempt = prepare(encoded)) {
            assertTrue(attempt.summary().requiresConfirmation()); assertEquals(0, attempt.summary().thisPaymentUnfinished());
        }
        psbt = AntiExfilPsbt.parseCanonicalV0(raw);
        psbt.getPsbtInputs().getFirst().getProprietary().put("017800", "01");
        try(var attempt = prepare(psbt.serialize())) {
            assertTrue(attempt.summary().requiresConfirmation()); assertEquals(1, attempt.summary().thisPaymentUnfinished());
        }
        try(var attempt = prepare()) { assertTrue(attempt.summary().requiresConfirmation()); }
    }
    private static int uniqueOffset(byte[] bytes, byte[] needle) {
        int match = -1;
        for(int i = 0; i <= bytes.length - needle.length; i++) {
            if(Arrays.equals(bytes, i, i + needle.length, needle, 0, needle.length)) {
                assertEquals(-1, match, "Fixture substructure must be unique"); match = i;
            }
        }
        assertTrue(match >= 0); return match;
    }
    @Test void t11ApprovalCannotBeInheritedByAnotherPreparedContext() {
        try(var c = start()) { c.acceptOpenings(openings(c)); }
        AntiExfilCoordinator.Approval stale;
        try(var first = prepare()) { stale = first.approve(); }
        try(var second = prepare()) { assertEquals(AntiExfilException.Code.RECOVERY_APPROVAL_REQUIRED,
                assertThrows(AntiExfilException.class, () -> second.start(stale)).getCode()); }
        try(var third = prepare()) { assertTrue(third.summary().requiresConfirmation()); }
    }
    @Test void t11ChangedHistoryInvalidatesAnAlreadyIssuedApproval() throws Exception {
        try(var c = start()) { c.acceptOpenings(openings(c)); }
        try(var attempt = prepare()) {
            var approval = attempt.approve();
            var field = attempt.getClass().getDeclaredField("history"); field.setAccessible(true);
            var history = (AntiExfilRecoveryHistory)field.get(attempt);
            var context = new AntiExfilRecoveryHistory.Context("01".repeat(32), "02".repeat(32), "03".repeat(32), 4);
            history.start(context, true); history.end(context, "USER_ABANDONED", false);
            assertEquals(AntiExfilException.Code.RECOVERY_APPROVAL_REQUIRED,
                    assertThrows(AntiExfilException.class, () -> attempt.start(approval)).getCode());
        }
    }
    @Test void t10FailedCompletionBarrierCannotReleaseVerifiedResult() throws Exception {
        try(var c = start()) {
            byte[] response = sign(c.acceptOpenings(openings(c)));
            var historyField = c.getClass().getDeclaredField("history"); historyField.setAccessible(true);
            var history = (AntiExfilRecoveryHistory)historyField.get(c);
            var writer = AntiExfilRecoveryHistory.class.getDeclaredField("writer"); writer.setAccessible(true);
            writer.set(history, (AntiExfilRecoveryHistory.FrameWriter)(path, body) ->
                    AntiExfilDurableFiles.write(path, body, true, 4096, parent -> { throw new java.io.IOException("completion barrier probe"); }));
            assertEquals(AntiExfilException.Code.HISTORY_STORAGE_ERROR, assertThrows(AntiExfilException.class, () -> c.complete(response)).getCode());
            assertThrows(AntiExfilException.class, c::getCompletedResult);
        }
        assertEquals(AntiExfilException.Code.HISTORY_STORAGE_ERROR, assertThrows(AntiExfilException.class, this::prepare).getCode());
    }
    @Test void t10ApprovalAndStartWriteFailuresGenerateNoHostRandomness() throws Exception {
        try(var c = start()) { c.acceptOpenings(openings(c)); }
        for(int failOn : List.of(1, 2)) {
            try(var attempt = prepare()) {
                var approval = attempt.approve();
                var historyField = attempt.getClass().getDeclaredField("history"); historyField.setAccessible(true);
                var history = (AntiExfilRecoveryHistory)historyField.get(attempt);
                var writer = AntiExfilRecoveryHistory.class.getDeclaredField("writer"); writer.setAccessible(true);
                java.util.concurrent.atomic.AtomicInteger writes = new java.util.concurrent.atomic.AtomicInteger();
                writer.set(history, (AntiExfilRecoveryHistory.FrameWriter)(path, body) -> {
                    if(writes.incrementAndGet() == failOn) throw new java.io.IOException("before-move probe");
                    AntiExfilDurableFiles.write(path, body, true, 4096);
                });
                java.util.concurrent.atomic.AtomicInteger randomCalls = new java.util.concurrent.atomic.AtomicInteger();
                var random = new java.security.SecureRandom() { @Override public void nextBytes(byte[] value) { randomCalls.incrementAndGet(); Arrays.fill(value, (byte)1); } };
                var start = attempt.getClass().getDeclaredMethod("start", AntiExfilCoordinator.Approval.class, java.security.SecureRandom.class);
                start.setAccessible(true);
                var error = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> start.invoke(attempt, approval, random));
                assertInstanceOf(AntiExfilException.class, error.getCause()); assertEquals(0, randomCalls.get());
            }
        }
    }
    @Test void t13NoApplicationTranscriptOrRandomnessPersistenceAndNoRestore() throws Exception {
        byte[] reveal;
        try(var c = start()) { reveal = c.acceptOpenings(openings(c)); c.complete(sign(reveal)); }
        try(var paths = Files.walk(temporary)) {
            for(Path path : paths.filter(Files::isRegularFile).toList()) {
                String hex = Utils.bytesToHex(Files.readAllBytes(path));
                assertFalse(hex.contains(Utils.bytesToHex(reveal)));
                for(var slot : AntiExfilCodec.decode(reveal).getSlots()) assertFalse(hex.contains(Utils.bytesToHex(slot.getHostRandomness())));
            }
        }
        assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.load(temporary.resolve("absent.aexs"), temporary.resolve("ram.aexj"), signer));
    }
}
