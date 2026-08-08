package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
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
    void recordsPostRevealAbortsAgainstWalletIdentityAndRequiresAcknowledgement() {
        AntiExfilCoordinator coordinator = create(session);
        assertThrows(AntiExfilException.class, () -> coordinator.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.USER_ABANDONED));
        coordinator.acceptOpenings(message2);
        coordinator.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.SIGNER_CANCELLED);
        coordinator.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.TRANSPORT_FAILED);

        AntiExfilCoordinator reloaded = AntiExfilCoordinator.load(session, journal, keystore);
        assertEquals(2, reloaded.getStatus().getPostRevealAbortCount());
        List<AntiExfilAbortJournal.AbortEvent> events = new AntiExfilAbortJournal(journal,
                walletIdentityForTest(keystore)).getEvents();
        assertEquals(2, events.size());
        assertArrayEquals(AntiExfilCodec.decode(message1).getSessionId(), events.getFirst().getSessionId());

        Path fresh = temporary.resolve("fresh.aexs");
        AntiExfilException blocked = assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.create(
                fresh, journal, raw, keystore, AntiExfilNetwork.TESTNET4, false, new VectorRandom()));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, blocked.getCode());
        assertFalse(Files.exists(fresh));
        AntiExfilCoordinator acknowledged = AntiExfilCoordinator.create(
                fresh, journal, raw, keystore, AntiExfilNetwork.TESTNET4, true, new VectorRandom());
        assertEquals(2, acknowledged.getStatus().getPostRevealAbortCount());
    }

    @Test
    void failsClosedOnCorruptStateAndWrongWallet() throws Exception {
        create(session);
        byte[] corrupt = Files.readAllBytes(session);
        corrupt[corrupt.length - 1] ^= 1;
        Files.write(session, corrupt);
        AntiExfilException checksum = assertThrows(AntiExfilException.class,
                () -> AntiExfilCoordinator.load(session, journal, keystore));
        assertEquals(AntiExfilException.Code.STATE_INVALID, checksum.getCode());

        Path otherSession = temporary.resolve("other.aexs");
        create(otherSession);
        Keystore other = keystore("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        AntiExfilException wrongWallet = assertThrows(AntiExfilException.class,
                () -> AntiExfilCoordinator.load(otherSession, journal, other));
        assertEquals(AntiExfilException.Code.STATE_INVALID, wrongWallet.getCode());
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
        return Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }

    private static byte[] repeat(byte value) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, value);
        return bytes;
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
