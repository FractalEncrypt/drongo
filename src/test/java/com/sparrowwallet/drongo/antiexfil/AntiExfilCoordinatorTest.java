package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.MnemonicException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class AntiExfilCoordinatorTest {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    private String vector;
    private byte[] raw;
    private byte[] message1;
    private byte[] message2;
    private byte[] message4;
    private Keystore keystore;
    private Path session;
    private Path journal;

    @BeforeEach
    void setup() throws IOException, MnemonicException {
        try(InputStream stream = getClass().getResourceAsStream("protocol-v1-semantic-psbt-vector.json")) {
            assertNotNull(stream);
            vector = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
        raw = Utils.hexToBytes(field("psbt_hex"));
        message1 = Utils.hexToBytes(field("message_1_hex"));
        message4 = Utils.hexToBytes(field("message_4_hex"));
        AntiExfilMessage signatures = AntiExfilCodec.decode(message4);
        List<AntiExfilSlot> openingSlots = signatures.getSlots().stream()
                .map(slot -> new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                        slot.getMessageHash(), slot.getCommitment(), slot.getOpening(), null, null)).toList();
        message2 = AntiExfilCodec.encode(new AntiExfilMessage(signatures.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                signatures.getSessionId(), signatures.getPsbtDigest(), openingSlots));
        keystore = keystore(WORDS);
        session = temporary.resolve("session.aexs");
        journal = temporary.resolve("wallet.aexj");
    }

    @Test
    void persistsFrozenSessionBeforeReturningExactReveal() {
        AntiExfilCoordinator coordinator = create(session);
        assertArrayEquals(message1, coordinator.getHostCommitMessage());
        assertArrayEquals(raw, coordinator.getFrozenPsbt());
        byte[] reveal = coordinator.acceptOpenings(message2);

        AntiExfilCoordinator reloaded = AntiExfilCoordinator.load(session, journal, keystore);
        assertEquals(AntiExfilCoordinator.Phase.OPENINGS_ACCEPTED, reloaded.getStatus().getPhase());
        assertArrayEquals(reveal, reloaded.getHostRevealMessage());
        assertArrayEquals(reveal, reloaded.acceptOpenings(message2));
        AntiExfilMessage decoded = AntiExfilCodec.decode(reveal);
        assertEquals(AntiExfilStage.HOST_REVEAL, decoded.getStage());
        for(int i = 0; i < decoded.getSlots().size(); i++) {
            assertArrayEquals(repeat((byte)(0x80 + i)), decoded.getSlots().get(i).getHostRandomness());
        }
    }

    @Test
    void rejectsChangedOpeningAfterDurableAcceptance() {
        AntiExfilCoordinator coordinator = create(session);
        coordinator.acceptOpenings(message2);
        AntiExfilMessage original = AntiExfilCodec.decode(message2);
        List<AntiExfilSlot> changed = new ArrayList<>(original.getSlots());
        AntiExfilSlot first = changed.getFirst();
        changed.set(0, new AntiExfilSlot(first.getInputIndex(), first.getSighashType(), first.getSignerPublicKey(),
                first.getMessageHash(), first.getCommitment(), changed.get(1).getOpening(), null, null));
        byte[] changedMessage = AntiExfilCodec.encode(new AntiExfilMessage(original.getNetwork(), original.getStage(),
                original.getSessionId(), original.getPsbtDigest(), changed));
        AntiExfilException exception = assertThrows(AntiExfilException.class, () -> coordinator.acceptOpenings(changedMessage));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, exception.getCode());
    }

    @Test
    void reconstructsOnlyVerifiedSignaturesAndNeverBroadcasts() {
        AntiExfilCoordinator coordinator = create(session);
        coordinator.acceptOpenings(message2);
        AntiExfilCoordinator.Completion completed = coordinator.complete(message4);
        assertFalse(completed.isBroadcast());
        assertEquals(field("signed_psbt_sha256"), Utils.bytesToHex(Sha256Hash.hash(completed.getSignedPsbt())));

        AntiExfilCoordinator reloaded = AntiExfilCoordinator.load(session, journal, keystore);
        assertEquals(AntiExfilCoordinator.Phase.COMPLETE, reloaded.getStatus().getPhase());
        assertFalse(reloaded.getStatus().isBroadcast());
        assertArrayEquals(completed.getSignedPsbt(), reloaded.complete(message4).getSignedPsbt());
        assertArrayEquals(completed.getSignedPsbt(), reloaded.getCompletedResult().getSignedPsbt());

        byte[] changed = message4.clone();
        changed[changed.length - 1] ^= 1;
        AntiExfilException exception = assertThrows(AntiExfilException.class, () -> reloaded.complete(changed));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, exception.getCode());
    }

    @Test
    void derivesIdenticalImmutableSignatureProofsAtCompletionAndAfterReload() {
        assertEquals(0, VerifiedAntiExfilSignature.class.getConstructors().length);
        AntiExfilCoordinator coordinator = create(session);
        coordinator.acceptOpenings(message2);
        AntiExfilCoordinator.Completion completed = coordinator.complete(message4);

        Set<VerifiedAntiExfilSignature> fresh = completed.getVerifiedSignatures();
        assertEquals(5, fresh.size());
        assertThrows(UnsupportedOperationException.class, fresh::clear);

        AntiExfilMessage commit = AntiExfilCodec.decode(message1);
        AntiExfilMessage signatures = AntiExfilCodec.decode(message4);
        VerifiedAntiExfilSignature first = fresh.stream()
                .filter(proof -> proof.getInputIndex() == 0)
                .findFirst().orElseThrow();
        assertArrayEquals(commit.getSessionId(), first.getSessionId());
        assertArrayEquals(Sha256Hash.hash(raw), first.getOriginalPsbtDigest());
        assertArrayEquals(AntiExfilCoordinator.getWalletKeyIdentity(keystore), first.getWalletKeyIdentity());
        assertArrayEquals(signatures.getSlots().getFirst().getSignerPublicKey(), first.getSignerPublicKey());
        assertArrayEquals(signatures.getSlots().getFirst().getMessageHash(), first.getMessageHash());
        assertArrayEquals(signatures.getSlots().getFirst().getSignature(), first.getCompactSignature());
        assertEquals(AntiExfilCodec.SIGHASH_ALL, first.getSighashType());
        assertEquals(36, first.getOutpoint().length);

        byte[] mutated = first.getCompactSignature();
        mutated[0] ^= 1;
        assertArrayEquals(signatures.getSlots().getFirst().getSignature(), first.getCompactSignature());

        AntiExfilCoordinator reloaded = AntiExfilCoordinator.load(session, journal, keystore);
        assertEquals(fresh, reloaded.getCompletedResult().getVerifiedSignatures());
        assertEquals(fresh, reloaded.complete(message4).getVerifiedSignatures());
    }

    @Test
    void admitsOnlySupportedNewSessionsButPreservesCompletedEvidenceAfterPolicyChange() {
        Keystore unsupported = keystore.copy();
        unsupported.setAntiExfilPolicy(AntiExfilKeystorePolicy.UNSUPPORTED);
        Path unsupportedSession = temporary.resolve("unsupported.aexs");
        AntiExfilException rejected = assertThrows(AntiExfilException.class,
                () -> AntiExfilCoordinator.create(unsupportedSession, temporary.resolve("unsupported.aexj"),
                        raw, unsupported, AntiExfilNetwork.TESTNET4));
        assertEquals(AntiExfilException.Code.STATE_INVALID, rejected.getCode());
        assertFalse(Files.exists(unsupportedSession));

        Keystore required = keystore.copy();
        required.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED);
        assertDoesNotThrow(() -> AntiExfilCoordinator.create(temporary.resolve("required.aexs"),
                temporary.resolve("required.aexj"), raw, required, AntiExfilNetwork.TESTNET4));

        AntiExfilCoordinator completed = create(session);
        completed.acceptOpenings(message2);
        Set<VerifiedAntiExfilSignature> evidence = completed.complete(message4).getVerifiedSignatures();
        keystore.setAntiExfilPolicy(AntiExfilKeystorePolicy.UNSUPPORTED);
        assertEquals(evidence, AntiExfilCoordinator.load(session, journal, keystore)
                .getCompletedResult().getVerifiedSignatures());
    }

    @Test
    void recordsPostRevealAbortsAgainstWalletIdentityAndRequiresAcknowledgement() {
        AntiExfilCoordinator coordinator = create(session);
        assertThrows(AntiExfilException.class, () -> coordinator.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.USER_ABANDONED));
        coordinator.acceptOpenings(message2);
        AntiExfilAbortJournal.AbortEvent first = coordinator.recordPostRevealAbort(
                AntiExfilCoordinator.AbortReason.SIGNER_CANCELLED);
        AntiExfilAbortJournal.AbortEvent duplicate = coordinator.recordPostRevealAbort(
                AntiExfilCoordinator.AbortReason.TRANSPORT_FAILED);
        assertEquals(first.getRecordedAtEpochSecond(), duplicate.getRecordedAtEpochSecond());
        assertEquals(AntiExfilCoordinator.AbortReason.SIGNER_CANCELLED.name(), duplicate.getReason());

        AntiExfilCoordinator reloaded = AntiExfilCoordinator.load(session, journal, keystore);
        assertEquals(1, reloaded.getStatus().getPostRevealAbortCount());
        List<AntiExfilAbortJournal.AbortEvent> events = new AntiExfilAbortJournal(journal,
                walletIdentityForTest(keystore)).getEvents();
        assertEquals(1, events.size());
        assertArrayEquals(AntiExfilCodec.decode(message1).getSessionId(), events.getFirst().getSessionId());

        Path fresh = temporary.resolve("fresh.aexs");
        AntiExfilException blocked = assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.create(
                fresh, journal, raw, keystore, AntiExfilNetwork.TESTNET4, false, new VectorRandom()));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, blocked.getCode());
        assertFalse(Files.exists(fresh));
        AntiExfilCoordinator acknowledged = AntiExfilCoordinator.create(
                fresh, journal, raw, keystore, AntiExfilNetwork.TESTNET4, true, new VectorRandom());
        assertEquals(1, acknowledged.getStatus().getPostRevealAbortCount());
    }

    @Test
    void failsClosedOnCorruptStateAndWrongWallet() throws Exception {
        create(session);
        byte[] corrupt = Files.readAllBytes(session);
        corrupt[corrupt.length - 1] ^= 1;
        Files.write(session, corrupt);
        List<String> corruptBefore = treeFingerprint(temporary);
        AntiExfilException checksum = assertThrows(AntiExfilException.class,
                () -> AntiExfilCoordinator.load(session, journal, keystore));
        assertEquals(AntiExfilException.Code.STATE_INVALID, checksum.getCode());
        assertEquals(corruptBefore, treeFingerprint(temporary));

        Path otherSession = temporary.resolve("other.aexs");
        create(otherSession);
        Keystore other = keystore("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        List<String> wrongWalletBefore = treeFingerprint(temporary);
        AntiExfilException wrongWallet = assertThrows(AntiExfilException.class,
                () -> AntiExfilCoordinator.load(otherSession, journal, other));
        assertEquals(AntiExfilException.Code.STATE_INVALID, wrongWallet.getCode());
        assertEquals(wrongWalletBefore, treeFingerprint(temporary));
    }

    @Test
    void missingSessionLoadIsStatePreservingAcrossRepeatedFreshDirectories() throws Exception {
        for(int i = 0; i < 100; i++) {
            Path parent = temporary.resolve("missing-" + i);
            Files.createDirectory(parent);
            Files.writeString(parent.resolve("sentinel.txt"), "unchanged-" + i, StandardCharsets.US_ASCII);
            Path missingSession = parent.resolve("session.aexs");
            Path missingJournal = parent.resolve("wallet.aexj");
            List<String> before = treeFingerprint(parent);

            AntiExfilException missing = assertThrows(AntiExfilException.class,
                    () -> AntiExfilCoordinator.load(missingSession, missingJournal, keystore));

            assertEquals(AntiExfilException.Code.STATE_INVALID, missing.getCode());
            assertEquals("Cannot access durable anti-exfil state: Coordinator session does not exist",
                    missing.getMessage());
            assertEquals(before, treeFingerprint(parent));
            assertFalse(Files.exists(missingSession));
            assertFalse(Files.exists(Path.of(missingSession + ".lock")));
            assertFalse(Files.exists(missingJournal));
            assertFalse(Files.exists(Path.of(missingJournal + ".lock")));
            try(var children = Files.list(parent)) {
                assertEquals(List.of("sentinel.txt"), children.map(path -> path.getFileName().toString()).sorted().toList());
            }
        }
    }

    @Test
    void refusesCompletionBeforeOpeningsAndAbortAfterCompletion() {
        AntiExfilCoordinator coordinator = create(session);
        assertThrows(AntiExfilException.class, () -> coordinator.complete(message4));
        coordinator.acceptOpenings(message2);
        coordinator.complete(message4);
        assertThrows(AntiExfilException.class, () -> coordinator.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.USER_ABANDONED));
    }

    private AntiExfilCoordinator create(Path path) {
        return AntiExfilCoordinator.create(path, journal, raw, keystore, AntiExfilNetwork.TESTNET4,
                false, new VectorRandom());
    }

    private static Keystore keystore(String words) throws MnemonicException {
        DeterministicSeed seed = new DeterministicSeed(words, "", 0, DeterministicSeed.Type.BIP39);
        Keystore keystore = Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
        keystore.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
        return keystore;
    }

    private static byte[] repeat(byte value) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, value);
        return bytes;
    }

    private static List<String> treeFingerprint(Path root) throws IOException {
        try(var paths = Files.walk(root)) {
            return paths.filter(path -> !path.equals(root))
                    .sorted()
                    .map(path -> {
                        Path relative = root.relativize(path);
                        if(Files.isDirectory(path)) return "D " + relative;
                        try {
                            byte[] bytes = Files.readAllBytes(path);
                            return "F " + relative + " " + bytes.length + " "
                                    + Utils.bytesToHex(Sha256Hash.hash(bytes));
                        } catch(IOException e) {
                            throw new java.io.UncheckedIOException(e);
                        }
                    })
                    .toList();
        } catch(java.io.UncheckedIOException e) {
            throw e.getCause();
        }
    }

    private String field(String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static byte[] walletIdentityForTest(Keystore keystore) {
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        bytes.writeBytes(keystore.getExtendedPublicKey().getKey().getPubKey());
        bytes.writeBytes(keystore.getExtendedPublicKey().getKey().getChainCode());
        bytes.writeBytes(keystore.getKeyDerivation().toString().getBytes(StandardCharsets.US_ASCII));
        return Sha256Hash.hash(bytes.toByteArray());
    }

    private static final class VectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'z' : (byte)(0x7f + call - 1));
        }
    }
}
