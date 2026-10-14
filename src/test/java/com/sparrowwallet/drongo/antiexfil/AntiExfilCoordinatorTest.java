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

    @Test void retainsFrozenCommitmentAndExactRevealOnlyInRam() throws Exception {
        try(var c = create(session)) {
            assertArrayEquals(message1, c.getHostCommitMessage());
            byte[] copy = c.getFrozenPsbt(); copy[0] ^= 1; assertArrayEquals(raw, c.getFrozenPsbt());
            byte[] reveal = c.acceptOpenings(message2);
            assertArrayEquals(reveal, c.acceptOpenings(message2)); assertArrayEquals(reveal, c.getHostRevealMessage());
            assertFalse(Files.exists(session)); assertFalse(Files.exists(journal)); assertNoRevealOnDisk(reveal);
        }
    }
    @Test void completionResolvesOnlyOwnedSessionAndReturnsExactSignatureMetadata() throws Exception {
        try(var c = create(session)) {
            byte[] reveal = c.acceptOpenings(message2); var result = c.complete(message4);
            assertFalse(result.isBroadcast()); assertEquals(5, result.getVerifiedSignatures().size());
            assertSame(result, c.getCompletedResult()); assertThrows(AntiExfilException.class, c::getHostRevealMessage);
            assertNoRevealOnDisk(reveal);
        }
        try(var next = AntiExfilCoordinator.create(null, journal, raw, keystore, AntiExfilNetwork.TESTNET4)) {
            assertNotNull(next.getHostCommitMessage());
        }
    }
    @Test void legacyBooleanCannotOverrideUncertaintyAndRestartCannotRestoreRam() {
        try(var c = create(session)) { c.acceptOpenings(message2); }
        assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.load(session, journal, keystore));
        assertEquals(AntiExfilException.Code.RECOVERY_APPROVAL_REQUIRED, assertThrows(AntiExfilException.class,
                () -> AntiExfilCoordinator.create(null, journal, raw, keystore, AntiExfilNetwork.TESTNET4, true)).getCode());
    }
    @Test void cancellingBeforeRevealAllowsAnotherFreshAttempt() {
        try(var c = create(session)) { }
        try(var next = AntiExfilCoordinator.create(null, journal, raw, keystore, AntiExfilNetwork.TESTNET4)) { assertNotNull(next.getHostCommitMessage()); }
    }
    @Test void sameAccountCannotPrecreateASecondWindow() {
        try(var first = create(session)) {
            assertEquals(AntiExfilException.Code.ACCOUNT_EXCHANGE_BUSY, assertThrows(AntiExfilException.class,
                    () -> AntiExfilCoordinator.create(null, journal, raw, keystore, AntiExfilNetwork.TESTNET4)).getCode());
            assertNotNull(first.acceptOpenings(message2));
        }
    }
    @Test void changedOpeningsEndTheExchangeWithoutReleasingNewReveal() {
        try(var c = create(session)) {
            c.acceptOpenings(message2); assertThrows(AntiExfilException.class, () -> c.acceptOpenings(foreign(message2)));
            assertThrows(AntiExfilException.class, c::getHostRevealMessage);
        }
    }
    @Test void foreignSignaturesCannotCompleteAndLeaveUncertainty() {
        try(var c = create(session)) {
            c.acceptOpenings(message2); assertThrows(AntiExfilException.class, () -> c.complete(foreign(message4)));
            assertThrows(AntiExfilException.class, c::getCompletedResult);
        }
        assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.create(null, journal, raw, keystore, AntiExfilNetwork.TESTNET4));
    }
    @Test void invalidSignatureCannotReleaseCompletion() {
        try(var c = create(session)) {
            c.acceptOpenings(message2); var valid = AntiExfilCodec.decode(message4); var slots = new ArrayList<>(valid.getSlots()); var first = slots.getFirst();
            byte[] invalid = new byte[64]; invalid[31] = invalid[63] = 1;
            slots.set(0, new AntiExfilSlot(first.getInputIndex(), first.getSighashType(), first.getSignerPublicKey(), first.getMessageHash(), first.getCommitment(), first.getOpening(), null, invalid));
            byte[] bad = AntiExfilCodec.encode(new AntiExfilMessage(valid.getNetwork(), valid.getStage(), valid.getSessionId(), valid.getPsbtDigest(), slots));
            assertThrows(AntiExfilException.class, () -> c.complete(bad)); assertThrows(AntiExfilException.class, c::getCompletedResult);
        }
    }
    @Test void oldBinaryWritePreventsRevealAndResultRelease() throws Exception {
        var c = create(session); Files.write(journal, new byte[]{1,2,3});
        assertEquals(AntiExfilException.Code.VERSION_CONFLICT, assertThrows(AntiExfilException.class, () -> c.acceptOpenings(message2)).getCode());
        c.close(); assertThrows(AntiExfilException.class, c::getHostRevealMessage);
    }
    @Test void unavailableResolutionNeverReleasesVerifiedResult() throws Exception {
        var c = create(session); c.acceptOpenings(message2); Files.write(journal, new byte[]{1,2,3});
        assertThrows(AntiExfilException.class, () -> c.complete(message4)); assertThrows(AntiExfilException.class, c::getCompletedResult); c.close();
    }
    @Test void legacySessionRestoreNeverReadsOrMutatesSecretFile() throws Exception {
        Files.write(session, new byte[]{'A','E','X','S',2,1,99}); byte[] before = Files.readAllBytes(session);
        assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.load(session, journal, keystore));
        assertArrayEquals(before, Files.readAllBytes(session)); assertFalse(Files.exists(journal));
    }
    @Test void unsupportedKeystoreIsRefusedAndLegacyRequiredRemainsOptional() {
        keystore.setAntiExfilPolicy(AntiExfilKeystorePolicy.UNSUPPORTED); assertThrows(AntiExfilException.class, () -> create(session));
        keystore.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED); assertTrue(keystore.supportsAntiExfil()); assertFalse(keystore.isAntiExfilRequired());
        try(var c = create(session)) { assertNotNull(c.getHostCommitMessage()); }
    }
    @Test void changedOriginCannotCreateASeparateAccountLease() {
        Keystore alias = keystore.copy(); alias.setKeyDerivation(new KeyDerivation("00000000", keystore.getKeyDerivation().getDerivationPath()));
        assertArrayEquals(AntiExfilCoordinator.getSigningKeyHistoryIdentity(keystore), AntiExfilCoordinator.getSigningKeyHistoryIdentity(alias));
        try(var c = create(session)) {
            assertEquals(AntiExfilException.Code.ACCOUNT_EXCHANGE_BUSY, assertThrows(AntiExfilException.class,
                    () -> AntiExfilCoordinator.create(null, temporary.resolve("alias.aexj"), withOrigin("00000000"), alias, AntiExfilNetwork.TESTNET4)).getCode());
        }
    }

    private byte[] withOrigin(String fingerprint) {
        var psbt=AntiExfilPsbt.parseCanonicalV0(raw);
        for(var input:psbt.getPsbtInputs()) {
            for(var entry:input.getDerivedPublicKeys().entrySet()) {
                if(entry.getValue().getMasterFingerprint().equals(keystore.getKeyDerivation().getMasterFingerprint())) {
                    entry.setValue(new KeyDerivation(fingerprint,entry.getValue().getDerivationPath()));
                }
            }
        }
        return psbt.serialize();
    }
    private void assertNoRevealOnDisk(byte[] reveal) throws Exception {
        try(var files=Files.walk(temporary)) {
            for(Path file:files.filter(Files::isRegularFile).toList()) {
                if(file.getFileName().toString().equals("exchange.lease")) { assertEquals(0, Files.size(file)); continue; }
                String bytes=Utils.bytesToHex(Files.readAllBytes(file));
                assertFalse(bytes.contains(Utils.bytesToHex(reveal)));
                for(AntiExfilSlot slot:AntiExfilCodec.decode(reveal).getSlots()) assertFalse(bytes.contains(Utils.bytesToHex(slot.getHostRandomness())));
            }
        }
    }
    private byte[] openingsFor(AntiExfilCoordinator coordinator) {
        var commit=AntiExfilCodec.decode(coordinator.getHostCommitMessage());var template=AntiExfilCodec.decode(message4);
        List<AntiExfilSlot> slots=new ArrayList<>();
        for(int i=0;i<commit.getSlots().size();i++) {var slot=commit.getSlots().get(i);slots.add(new AntiExfilSlot(slot.getInputIndex(),slot.getSighashType(),slot.getSignerPublicKey(),slot.getMessageHash(),slot.getCommitment(),template.getSlots().get(i).getOpening(),null,null));}
        return AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(),AntiExfilStage.SIGNER_OPENINGS,commit.getSessionId(),commit.getPsbtDigest(),slots));
    }
    private byte[] foreign(byte[] encoded) {var m=AntiExfilCodec.decode(encoded);byte[] id=m.getSessionId();id[0]^=1;return AntiExfilCodec.encode(new AntiExfilMessage(m.getNetwork(),m.getStage(),id,m.getPsbtDigest(),m.getSlots()));}

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
