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
    void retainsFrozenCommitmentAndExactRevealOnlyInRam() throws Exception {
        var coordinator = create(session);
        assertArrayEquals(message1, coordinator.getHostCommitMessage());
        byte[] original = coordinator.getFrozenPsbt(); original[0] ^= 1;
        assertArrayEquals(raw, coordinator.getFrozenPsbt());
        byte[] reveal = coordinator.acceptOpenings(message2);
        assertArrayEquals(reveal, coordinator.acceptOpenings(message2));
        assertArrayEquals(reveal, coordinator.getHostRevealMessage());
        assertFalse(Files.exists(session));
        assertFalse(Files.exists(session.resolveSibling("session.aexs.lock")));
        assertEquals("PENDING_REVEAL", events().getFirst().getReason());
        assertNoRevealOnDisk(reveal);
    }

    @Test
    void completionResolvesHistoryAndRetainsOnlyExactSignatureStatus() throws Exception {
        var coordinator = create(session);
        byte[] reveal = coordinator.acceptOpenings(message2);
        var completion = coordinator.complete(message4);
        assertFalse(completion.isBroadcast());
        assertEquals(5, completion.getVerifiedSignatures().size());
        assertEquals(Set.of("PENDING_REVEAL", "VERIFIED_COMPLETE"), events().stream().map(AntiExfilAbortJournal.AbortEvent::getReason).collect(java.util.stream.Collectors.toSet()));
        assertThrows(AntiExfilException.class, coordinator::getHostRevealMessage);
        assertThrows(AntiExfilException.class, coordinator::getFrozenPsbt);
        assertSame(completion, coordinator.getCompletedResult());
        assertNoRevealOnDisk(reveal);
        assertDoesNotThrow(() -> AntiExfilCoordinator.create(null, journal, raw, keystore, AntiExfilNetwork.TESTNET4));
    }

    @Test
    void restartCannotRestoreStateOrOverridePendingWithAcknowledgement() {
        var coordinator = create(session);
        coordinator.acceptOpenings(message2);
        coordinator.close();
        assertEquals(AntiExfilCoordinator.Phase.CLOSED, coordinator.getStatus().getPhase());
        assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.load(session,journal,keystore));
        assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.create(null,journal,raw,keystore,AntiExfilNetwork.TESTNET4,true));
        assertThrows(AntiExfilException.class, coordinator::getHostRevealMessage);
        assertEquals("PENDING_REVEAL", events().getFirst().getReason());
    }

    @Test
    void cancellingBeforeRevealAllowsFreshAttempt() {
        var coordinator = create(session);
        coordinator.close();
        assertTrue(events().isEmpty());
        assertDoesNotThrow(() -> AntiExfilCoordinator.create(null,journal,raw,keystore,AntiExfilNetwork.TESTNET4));
    }

    @Test
    void explicitAbandonPreservesPendingAndDropsOwnedSecrets() {
        var coordinator = create(session);
        coordinator.acceptOpenings(message2);
        coordinator.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.USER_ABANDONED);
        assertEquals(List.of("PENDING_REVEAL", "USER_ABANDONED"), events().stream().map(AntiExfilAbortJournal.AbortEvent::getReason).toList());
        assertThrows(AntiExfilException.class, coordinator::getHostRevealMessage);
        assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.create(null,journal,raw,keystore,AntiExfilNetwork.TESTNET4,true));
    }

    @Test
    void duplicateWalletCannotGetFreshChallengeAfterPendingReveal() {
        var coordinator=create(session); coordinator.acceptOpenings(message2);
        Keystore duplicate=keystore.copy(); duplicate.setLabel("Another wallet / same account");
        assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.create(null,journal,raw,duplicate,AntiExfilNetwork.TESTNET4,true));
    }

    @Test
    void precreatedConcurrentSessionCannotRevealAfterFirstPendingMarker() {
        var first=create(session);
        var second=AntiExfilCoordinator.create(null,journal,raw,keystore,AntiExfilNetwork.TESTNET4);
        byte[] secondOpenings=openingsFor(second);
        first.acceptOpenings(message2);
        assertThrows(AntiExfilException.class, () -> second.acceptOpenings(secondOpenings));
        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED,second.getStatus().getPhase());
        assertEquals(1,events().size());
    }

    @Test
    void concurrentRevealReservationsHaveExactlyOneWinner() throws Exception {
        var first=create(session);
        var second=AntiExfilCoordinator.create(null,journal,raw,keystore,AntiExfilNetwork.TESTNET4);
        byte[] secondOpenings=openingsFor(second);
        java.util.concurrent.CountDownLatch start=new java.util.concurrent.CountDownLatch(1);
        try(var executor=java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var a=executor.submit(() -> {start.await(); try {first.acceptOpenings(message2);return true;}catch(AntiExfilException e){return false;}});
            var b=executor.submit(() -> {start.await(); try {second.acceptOpenings(secondOpenings);return true;}catch(AntiExfilException e){return false;}});
            start.countDown(); assertNotEquals(a.get(),b.get());
        }
        assertEquals(1,events().size());
    }

    @Test
    void changedOpeningsCannotChangeRevealOrHistory() {
        var coordinator=create(session); byte[] reveal=coordinator.acceptOpenings(message2);
        assertThrows(AntiExfilException.class,()->coordinator.acceptOpenings(foreign(message2)));
        assertArrayEquals(reveal,coordinator.getHostRevealMessage()); assertEquals(1,events().size());
    }

    @Test
    void foreignSignatureSessionCannotCompleteOrClearPending() {
        var coordinator=create(session); coordinator.acceptOpenings(message2);
        assertThrows(AntiExfilException.class,()->coordinator.complete(foreign(message4)));
        assertEquals("PENDING_REVEAL",events().getFirst().getReason());
        assertThrows(AntiExfilException.class,coordinator::getCompletedResult);
        assertThrows(AntiExfilException.class,()->AntiExfilCoordinator.create(null,journal,raw,keystore,AntiExfilNetwork.TESTNET4,true));
    }

    @Test
    void invalidSignatureCannotProduceCompletionOrResolution() {
        var coordinator=create(session); coordinator.acceptOpenings(message2);
        AntiExfilMessage valid=AntiExfilCodec.decode(message4);
        var slots=new ArrayList<>(valid.getSlots());var first=slots.getFirst();
        byte[] invalid=new byte[64];invalid[31]=1;invalid[63]=1;
        slots.set(0,new AntiExfilSlot(first.getInputIndex(),first.getSighashType(),first.getSignerPublicKey(),first.getMessageHash(),first.getCommitment(),first.getOpening(),null,invalid));
        byte[] bad=AntiExfilCodec.encode(new AntiExfilMessage(valid.getNetwork(),valid.getStage(),valid.getSessionId(),valid.getPsbtDigest(),slots));
        assertThrows(AntiExfilException.class,()->coordinator.complete(bad));
        assertThrows(AntiExfilException.class,coordinator::getCompletedResult);assertEquals(1,events().size());
    }

    @Test
    void corruptJournalPreventsReveal() throws Exception {
        var coordinator=create(session);Files.write(journal,new byte[]{1,2,3});
        assertThrows(AntiExfilException.class,()->coordinator.acceptOpenings(message2));
        assertThrows(AntiExfilException.class,coordinator::getHostRevealMessage);
    }

    @Test
    void unavailableResolutionNeverReleasesVerifiedResult() throws Exception {
        var coordinator=create(session);coordinator.acceptOpenings(message2);Files.write(journal,new byte[]{1,2,3});
        assertThrows(AntiExfilException.class,()->coordinator.complete(message4));
        assertThrows(AntiExfilException.class,coordinator::getCompletedResult);
    }

    @Test
    void legacyFilesAreNeverReadOrMutatedDuringRestore() throws Exception {
        Files.write(session,new byte[]{'A','E','X','S',2,1,99});byte[] original=Files.readAllBytes(session);
        assertThrows(AntiExfilException.class,()->AntiExfilCoordinator.load(session,journal,keystore));
        assertArrayEquals(original,Files.readAllBytes(session));assertFalse(Files.exists(journal));
    }

    @Test
    void legacyAbortHistoryIsPreservedAndNeverAcknowledgedAway() throws Exception {
        var log=new AntiExfilAbortJournal(journal,AntiExfilCoordinator.getSigningKeyHistoryIdentity(keystore));
        log.append(repeat((byte)1),repeat((byte)2),"USER_ABANDONED");
        // Construct a valid historical version-one journal without secret contents.
        byte[] body=AntiExfilDurableFiles.read(journal,4*1024*1024);body[4]=1;
        AntiExfilDurableFiles.write(journal,body,false,4*1024*1024);byte[] original=Files.readAllBytes(journal);
        assertThrows(AntiExfilException.class,()->AntiExfilCoordinator.create(null,journal,raw,keystore,AntiExfilNetwork.TESTNET4,true));
        assertArrayEquals(original,Files.readAllBytes(journal));assertEquals("USER_ABANDONED",events().getFirst().getReason());
    }

    @Test
    void unsupportedKeystoreIsRefusedAndLegacyRequiredIsOptional() {
        keystore.setAntiExfilPolicy(AntiExfilKeystorePolicy.UNSUPPORTED);
        assertThrows(AntiExfilException.class,()->create(session));
        keystore.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED);
        assertTrue(keystore.supportsAntiExfil());assertFalse(keystore.isAntiExfilRequired());
        assertDoesNotThrow(()->create(session));
    }

    @Test
    void changedOriginCannotGiveSameAccountASeparateHistoryDomain() {
        Keystore alias=keystore.copy();alias.setKeyDerivation(new KeyDerivation("00000000",keystore.getKeyDerivation().getDerivationPath()));
        assertFalse(Arrays.equals(AntiExfilCoordinator.getWalletKeyIdentity(keystore),AntiExfilCoordinator.getWalletKeyIdentity(alias)));
        assertArrayEquals(AntiExfilCoordinator.getSigningKeyHistoryIdentity(keystore),AntiExfilCoordinator.getSigningKeyHistoryIdentity(alias));
        var coordinator=create(session);coordinator.acceptOpenings(message2);
        byte[] aliasPsbt=withOrigin("00000000");
        assertDoesNotThrow(()->AntiExfilCoordinator.create(null,temporary.resolve("alias-control.aexj"),aliasPsbt,alias,AntiExfilNetwork.TESTNET4));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT,assertThrows(AntiExfilException.class,()->AntiExfilCoordinator.create(null,journal,aliasPsbt,alias,AntiExfilNetwork.TESTNET4,true)).getCode());
    }

    @Test
    void legacyMigrationPreservesOldJournalAndBlocksOriginAliases() throws Exception {
        Path legacy=temporary.resolve("old-origin.aexj");
        new AntiExfilAbortJournal(legacy,AntiExfilCoordinator.getWalletKeyIdentity(keystore)).append(repeat((byte)5),repeat((byte)6),"USER_ABANDONED");
        byte[] legacyBody=AntiExfilDurableFiles.read(legacy,4*1024*1024);legacyBody[4]=1;
        AntiExfilDurableFiles.write(legacy,legacyBody,false,4*1024*1024);
        byte[] before=Files.readAllBytes(legacy);
        AntiExfilCoordinator.preserveLegacyHistory(journal,legacy,false,keystore);
        assertArrayEquals(before,Files.readAllBytes(legacy));assertEquals("LEGACY_ACCOUNT_HISTORY",events().getFirst().getReason());
        Keystore alias=keystore.copy();alias.setKeyDerivation(new KeyDerivation("00000000",keystore.getKeyDerivation().getDerivationPath()));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT,assertThrows(AntiExfilException.class,()->AntiExfilCoordinator.create(null,journal,withOrigin("00000000"),alias,AntiExfilNetwork.TESTNET4,true)).getCode());
        AntiExfilCoordinator.preserveLegacyHistory(journal,legacy,false,keystore);assertEquals(1,events().size());
    }

    @Test
    void legacySessionPresenceBlocksWithoutOpeningOrDeletingSecretFile() throws Exception {
        Files.write(session,new byte[]{'A','E','X','S',99});byte[] before=Files.readAllBytes(session);
        AntiExfilCoordinator.preserveLegacyHistory(journal,temporary.resolve("absent-old-journal.aexj"),true,keystore);
        assertArrayEquals(before,Files.readAllBytes(session));assertFalse(Files.exists(temporary.resolve("absent-old-journal.aexj")));
        assertThrows(AntiExfilException.class,()->create(session));
    }

    private List<AntiExfilAbortJournal.AbortEvent> events() {return new AntiExfilAbortJournal(journal,AntiExfilCoordinator.getSigningKeyHistoryIdentity(keystore)).getEvents();}
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
