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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class AntiExfilAbortStateMachineTest {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");

    @TempDir
    Path temporary;

    private String vector;
    private byte[] raw;
    private byte[] message4;
    private Keystore keystore;
    private Path journal;

    @BeforeEach
    void setup() throws IOException, MnemonicException {
        try(InputStream stream = getClass().getResourceAsStream("protocol-v1-semantic-psbt-vector.json")) {
            assertNotNull(stream);
            vector = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
        raw = Utils.hexToBytes(field("psbt_hex"));
        message4 = Utils.hexToBytes(field("message_4_hex"));
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        keystore = Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
        journal = temporary.resolve("wallet.aexj");
    }

    @Test
    void abortAfterCreationRevokesFirstRevealButNotCachedExactRetry() {
        AntiExfilCoordinator first = create("first.aexs", (byte)0x11);
        AntiExfilCoordinator staged = create("staged.aexs", (byte)0x22);
        byte[] firstOpenings = openingsFor(first);
        byte[] stagedOpenings = openingsFor(staged);

        byte[] firstReveal = first.acceptOpenings(firstOpenings);
        first.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.SIGNER_CANCELLED);

        AntiExfilException revoked = assertThrows(AntiExfilException.class,
                () -> staged.acceptOpenings(stagedOpenings));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, revoked.getCode());
        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED, staged.getStatus().getPhase());
        assertArrayEquals(firstReveal, first.acceptOpenings(firstOpenings),
                "an exact retry returns only the already-disclosed cached reveal");
    }

    @Test
    void acknowledgedHistoryIsBoundAndLaterAbortStillRevokesReveal() {
        AntiExfilCoordinator first = create("first.aexs", (byte)0x31);
        first.acceptOpenings(openingsFor(first));
        first.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.USER_ABANDONED);

        AntiExfilCoordinator acknowledged = create("acknowledged.aexs", (byte)0x32, true);
        AntiExfilCoordinator later = create("later.aexs", (byte)0x33, true);
        later.acceptOpenings(openingsFor(later));
        later.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.TRANSPORT_FAILED);

        AntiExfilException revoked = assertThrows(AntiExfilException.class,
                () -> acknowledged.acceptOpenings(openingsFor(acknowledged)));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, revoked.getCode());
    }

    @Test
    void signerSignatureRejectionIsJournaledOnceWithFirstReason() throws IOException {
        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(temporary.resolve("signature.aexs"), journal,
                raw, keystore, AntiExfilNetwork.TESTNET4, false, new PinnedVectorRandom());
        coordinator.acceptOpenings(openingsFor(coordinator));
        byte[] invalid = invalidSignatures();

        AntiExfilException first = assertThrows(AntiExfilException.class, () -> coordinator.complete(invalid));
        assertEquals(AntiExfilException.Code.SIGNATURE_INVALID, first.getCode());
        byte[] afterFirst = Files.readAllBytes(journal);

        AntiExfilException repeated = assertThrows(AntiExfilException.class, () -> coordinator.complete(invalid));
        assertEquals(AntiExfilException.Code.SIGNATURE_INVALID, repeated.getCode());
        coordinator.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.USER_ABANDONED);

        List<AntiExfilAbortJournal.AbortEvent> events = events();
        assertEquals(1, events.size());
        assertEquals(AntiExfilCoordinator.AbortReason.SIGNATURE_REJECTED.name(), events.getFirst().getReason());
        assertArrayEquals(afterFirst, Files.readAllBytes(journal),
                "repeated automatic and manual recording must not rewrite the first event");
    }

    @Test
    void signerOpeningRejectionIsJournaledAndReturnsNoReveal() {
        AntiExfilCoordinator coordinator = create("opening.aexs", (byte)0x41);
        byte[] encoded = openingsFor(coordinator);
        byte[] malformed = Arrays.copyOf(encoded, encoded.length - 1);

        AntiExfilException rejected = assertThrows(AntiExfilException.class,
                () -> coordinator.acceptOpenings(malformed));
        assertEquals(AntiExfilException.Code.INVALID_MESSAGE, rejected.getCode());
        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED, coordinator.getStatus().getPhase());
        assertEquals(1, events().size());
        assertEquals(AntiExfilCoordinator.AbortReason.SIGNATURE_REJECTED.name(), events().getFirst().getReason());
    }

    @Test
    void transportBoundaryCanRecordSignerRejectionBeforeRevealIdempotently() throws IOException {
        AntiExfilCoordinator coordinator = create("transport-rejection.aexs", (byte)0x49);
        AntiExfilAbortJournal.AbortEvent first = coordinator.recordSignerDataRejection();
        byte[] journalBytes = Files.readAllBytes(journal);
        AntiExfilAbortJournal.AbortEvent repeated = coordinator.recordSignerDataRejection();

        assertEquals(AntiExfilCoordinator.AbortReason.SIGNATURE_REJECTED.name(), first.getReason());
        assertEquals(first.getRecordedAtEpochSecond(), repeated.getRecordedAtEpochSecond());
        assertArrayEquals(journalBytes, Files.readAllBytes(journal));
        assertEquals(1, events().size());
        assertTrue(AntiExfilCoordinator.isSignerDataRejection(
                new AntiExfilException(AntiExfilException.Code.SIGNATURE_INVALID, "invalid")));
        assertFalse(AntiExfilCoordinator.isSignerDataRejection(
                new AntiExfilException(AntiExfilException.Code.WRONG_STAGE, "wrong stage")));
    }

    @Test
    void wrongStageAndChangedExactRetryDoNotPoisonJournal() {
        AntiExfilCoordinator coordinator = create("retry.aexs", (byte)0x51);
        AntiExfilException wrongStage = assertThrows(AntiExfilException.class,
                () -> coordinator.acceptOpenings(coordinator.getHostCommitMessage()));
        assertEquals(AntiExfilException.Code.WRONG_STAGE, wrongStage.getCode());
        assertTrue(events().isEmpty());

        byte[] accepted = openingsFor(coordinator);
        coordinator.acceptOpenings(accepted);
        byte[] changed = accepted.clone();
        changed[changed.length - 1] ^= 1;
        AntiExfilException retry = assertThrows(AntiExfilException.class,
                () -> coordinator.acceptOpenings(changed));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, retry.getCode());
        assertTrue(events().isEmpty());
    }

    @Test
    void laterWalletAbortDoesNotPreventLegitimateCompletionAfterReveal() {
        AntiExfilCoordinator legitimate = AntiExfilCoordinator.create(temporary.resolve("legitimate.aexs"), journal,
                raw, keystore, AntiExfilNetwork.TESTNET4, false, new PinnedVectorRandom());
        AntiExfilCoordinator abandoned = create("abandoned.aexs", (byte)0x59);
        legitimate.acceptOpenings(openingsFor(legitimate));
        abandoned.acceptOpenings(openingsFor(abandoned));
        abandoned.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.SIGNER_CANCELLED);

        AntiExfilCoordinator.Completion completion = legitimate.complete(message4);
        assertFalse(completion.isBroadcast());
        assertArrayEquals(completion.getSignedPsbt(), legitimate.complete(message4).getSignedPsbt());
    }

    @Test
    void aliasedJournalPathsShareOneLockIdentityAndOneEvent() throws Exception {
        Path real = temporary.resolve("real");
        Path alias = temporary.resolve("alias");
        Files.createDirectory(real);
        try {
            Files.createSymbolicLink(alias, real);
        } catch(UnsupportedOperationException | IOException | SecurityException e) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, "symbolic links are unavailable: " + e.getMessage());
        }
        byte[] identity = AntiExfilCoordinator.getWalletKeyIdentity(keystore);
        AntiExfilAbortJournal direct = new AntiExfilAbortJournal(real.resolve("wallet.aexj"), identity);
        AntiExfilAbortJournal throughAlias = new AntiExfilAbortJournal(alias.resolve("wallet.aexj"), identity);
        byte[] sessionId = new byte[32];
        byte[] psbtDigest = new byte[32];
        Arrays.fill(sessionId, (byte)0x66);
        Arrays.fill(psbtDigest, (byte)0x77);

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<AntiExfilAbortJournal.AbortEvent> first = executor.submit(() ->
                    direct.append(sessionId, psbtDigest, AntiExfilCoordinator.AbortReason.SIGNER_CANCELLED.name()));
            Future<AntiExfilAbortJournal.AbortEvent> second = executor.submit(() ->
                    throughAlias.append(sessionId, psbtDigest, AntiExfilCoordinator.AbortReason.TRANSPORT_FAILED.name()));
            AntiExfilAbortJournal.AbortEvent one = first.get(5, TimeUnit.SECONDS);
            AntiExfilAbortJournal.AbortEvent two = second.get(5, TimeUnit.SECONDS);
            assertEquals(one.getRecordedAtEpochSecond(), two.getRecordedAtEpochSecond());
            assertEquals(one.getReason(), two.getReason());
            assertEquals(1, direct.getEvents().size());
            assertEquals(1, throughAlias.getEvents().size());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void versionOnePreRevealStateLoadsButCannotDiscloseUnboundRandomness() throws Exception {
        Path session = temporary.resolve("version-one-pre-reveal.aexs");
        AntiExfilCoordinator created = AntiExfilCoordinator.create(session, journal, raw, keystore,
                AntiExfilNetwork.TESTNET4, false, new PinnedVectorRandom());
        byte[] openings = openingsFor(created);
        downgradeStateToVersionOne(session);

        AntiExfilCoordinator legacy = AntiExfilCoordinator.load(session, journal, keystore);
        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED, legacy.getStatus().getPhase());
        AntiExfilException blocked = assertThrows(AntiExfilException.class,
                () -> legacy.acceptOpenings(openings));
        assertEquals(AntiExfilException.Code.RETRY_CONFLICT, blocked.getCode());
    }

    @Test
    void versionOnePostRevealStateRetainsExactRetryAndCompletion() throws Exception {
        Path session = temporary.resolve("version-one-post-reveal.aexs");
        AntiExfilCoordinator created = AntiExfilCoordinator.create(session, journal, raw, keystore,
                AntiExfilNetwork.TESTNET4, false, new PinnedVectorRandom());
        byte[] openings = openingsFor(created);
        byte[] reveal = created.acceptOpenings(openings);
        downgradeStateToVersionOne(session);

        AntiExfilCoordinator legacy = AntiExfilCoordinator.load(session, journal, keystore);
        assertArrayEquals(reveal, legacy.acceptOpenings(openings));
        AntiExfilCoordinator.Completion completion = legacy.complete(message4);
        assertFalse(completion.isBroadcast());
        assertArrayEquals(completion.getSignedPsbt(),
                AntiExfilCoordinator.load(session, journal, keystore).getCompletedResult().getSignedPsbt());
    }

    @Test
    void concurrentAbortCannotLeaveAUsableUnacknowledgedSession() throws Exception {
        assertTimeoutPreemptively(Duration.ofSeconds(15), () -> {
            AntiExfilCoordinator old = create("old.aexs", (byte)0x61);
            old.acceptOpenings(openingsFor(old));
            Path freshPath = temporary.resolve("fresh.aexs");
            Path lockPath = temporary.resolve("fresh.aexs.lock");

            try(LockHolder holder = LockHolder.acquire(lockPath)) {
                ExecutorService executor = Executors.newFixedThreadPool(2);
                try {
                    Future<AntiExfilCoordinator> fresh = executor.submit(() ->
                            AntiExfilCoordinator.create(freshPath, journal, raw, keystore,
                                    AntiExfilNetwork.TESTNET4, false, new DistinctVectorRandom((byte)0x62)));
                    holder.awaitContender();
                    Future<AntiExfilAbortJournal.AbortEvent> abort = executor.submit(() ->
                            old.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.SIGNER_CANCELLED));

                    Thread.sleep(150);
                    holder.close();
                    AntiExfilCoordinator created = fresh.get(5, TimeUnit.SECONDS);
                    abort.get(5, TimeUnit.SECONDS);

                    AntiExfilException revoked = assertThrows(AntiExfilException.class,
                            () -> created.acceptOpenings(openingsFor(created)));
                    assertEquals(AntiExfilException.Code.RETRY_CONFLICT, revoked.getCode());
                } finally {
                    executor.shutdownNow();
                }
            }
        });
    }

    private AntiExfilCoordinator create(String filename, byte sessionByte) {
        return create(filename, sessionByte, false);
    }

    private AntiExfilCoordinator create(String filename, byte sessionByte, boolean acknowledge) {
        return AntiExfilCoordinator.create(temporary.resolve(filename), journal, raw, keystore,
                AntiExfilNetwork.TESTNET4, acknowledge, new DistinctVectorRandom(sessionByte));
    }

    private byte[] openingsFor(AntiExfilCoordinator coordinator) {
        AntiExfilMessage commit = AntiExfilCodec.decode(coordinator.getHostCommitMessage());
        AntiExfilMessage template = AntiExfilCodec.decode(message4);
        assertEquals(commit.getSlots().size(), template.getSlots().size());
        List<AntiExfilSlot> slots = new ArrayList<>();
        for(int i = 0; i < commit.getSlots().size(); i++) {
            AntiExfilSlot authoritative = commit.getSlots().get(i);
            slots.add(new AntiExfilSlot(authoritative.getInputIndex(), authoritative.getSighashType(),
                    authoritative.getSignerPublicKey(), authoritative.getMessageHash(),
                    authoritative.getCommitment(), template.getSlots().get(i).getOpening(), null, null));
        }
        return AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS,
                commit.getSessionId(), commit.getPsbtDigest(), slots));
    }

    private byte[] invalidSignatures() {
        AntiExfilMessage valid = AntiExfilCodec.decode(message4);
        List<AntiExfilSlot> slots = new ArrayList<>(valid.getSlots());
        AntiExfilSlot first = slots.getFirst();
        byte[] invalid = new byte[64];
        invalid[31] = 1;
        invalid[63] = 1;
        slots.set(0, new AntiExfilSlot(first.getInputIndex(), first.getSighashType(), first.getSignerPublicKey(),
                first.getMessageHash(), first.getCommitment(), first.getOpening(), null, invalid));
        return AntiExfilCodec.encode(new AntiExfilMessage(valid.getNetwork(), valid.getStage(),
                valid.getSessionId(), valid.getPsbtDigest(), slots));
    }

    private List<AntiExfilAbortJournal.AbortEvent> events() {
        return new AntiExfilAbortJournal(journal,
                AntiExfilCoordinator.getWalletKeyIdentity(keystore)).getEvents();
    }

    private static void downgradeStateToVersionOne(Path session) throws IOException {
        byte[] encoded = Files.readAllBytes(session);
        byte[] body = Arrays.copyOf(encoded, encoded.length - 32);
        int cursor = 4 + 1 + 1 + 32;
        ByteBuffer view = ByteBuffer.wrap(body);
        for(int i = 0; i < 6; i++) {
            int length = view.getInt(cursor);
            cursor += 4;
            if(length >= 0) cursor += length;
        }
        int digestLength = view.getInt(cursor);
        assertEquals(32, digestLength);
        int afterDigest = cursor + 4 + digestLength;
        byte[] legacyBody = new byte[body.length - 4 - digestLength];
        System.arraycopy(body, 0, legacyBody, 0, cursor);
        System.arraycopy(body, afterDigest, legacyBody, cursor, body.length - afterDigest);
        legacyBody[4] = 1;
        byte[] legacy = ByteBuffer.allocate(legacyBody.length + 32)
                .put(legacyBody).put(Sha256Hash.hash(legacyBody)).array();
        Files.write(session, legacy);
    }

    private String field(String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static final class DistinctVectorRandom extends SecureRandom {
        private final byte sessionByte;
        private int call;

        private DistinctVectorRandom(byte sessionByte) {
            this.sessionByte = sessionByte;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? sessionByte : (byte)(0x70 + call));
        }
    }

    private static final class PinnedVectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'z' : (byte)(0x7f + call - 1));
        }
    }

    public static final class LockHolder implements AutoCloseable {
        private final Process process;
        private final BufferedReader output;
        private boolean closed;

        private LockHolder(Process process) {
            this.process = process;
            this.output = process.inputReader(StandardCharsets.UTF_8);
        }

        static LockHolder acquire(Path lockPath) throws IOException {
            String java = Path.of(System.getProperty("java.home"), "bin", isWindows() ? "java.exe" : "java").toString();
            Process process = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                    LockHolder.class.getName(), lockPath.toString()).redirectErrorStream(true).start();
            LockHolder holder = new LockHolder(process);
            assertEquals("LOCKED", holder.output.readLine());
            return holder;
        }

        void awaitContender() throws InterruptedException {
            Thread.sleep(250);
        }

        @Override
        public void close() throws IOException, InterruptedException {
            if(closed) return;
            closed = true;
            process.getOutputStream().close();
            assertTrue(process.waitFor(5, TimeUnit.SECONDS));
            assertEquals(0, process.exitValue());
        }

        public static void main(String[] args) throws Exception {
            Path lockPath = Path.of(args[0]);
            Files.createDirectories(lockPath.toAbsolutePath().getParent());
            try(FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                FileLock ignored = channel.lock()) {
                System.out.println("LOCKED");
                System.out.flush();
                System.in.readAllBytes();
            }
        }

        private static boolean isWindows() {
            return System.getProperty("os.name").toLowerCase().contains("win");
        }
    }
}
