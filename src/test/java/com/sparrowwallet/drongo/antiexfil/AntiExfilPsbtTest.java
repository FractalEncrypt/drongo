package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.MnemonicException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class AntiExfilPsbtTest {
    private static final String WORDS = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"");
    private String vector;
    private byte[] raw;
    private Keystore keystore;

    @BeforeEach
    void setup() throws IOException, MnemonicException {
        try(InputStream stream = getClass().getResourceAsStream("protocol-v1-semantic-psbt-vector.json")) {
            assertNotNull(stream);
            vector = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
        raw = Utils.hexToBytes(field("psbt_hex"));
        DeterministicSeed seed = new DeterministicSeed(WORDS, "", 0, DeterministicSeed.Type.BIP39);
        keystore = Keystore.fromSeed(seed, PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
    }

    @Test
    void enumeratesFrozenFixtureWithAuthoritativeSighashes() {
        List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(raw, keystore);
        assertEquals(5, slots.size());
        assertEquals(List.of(0, 1, 2, 2, 3), slots.stream().map(AntiExfilSigningSlot::getInputIndex).toList());
        assertEquals(List.of("p2wpkh", "p2sh-p2wpkh", "p2wsh-multisig", "p2wsh-multisig", "p2sh-p2wsh-multisig"),
                slots.stream().map(AntiExfilSigningSlot::getScriptKind).toList());
        assertEquals("fa4ef7e7bee778ec04017cd89c12da335d8e17fb3da749e3bfae070b0655d249",
                Utils.bytesToHex(Sha256Hash.hash(raw)));

        String[] expectedKeys = {
                "03909be3f1298f1337971ed6360dd95d456b2bda2c8f50879856e0a0fad38e2670",
                "02fc4323478d235a10d8053af51ec0d237fe8547629560a0ad61e077392a95a5cc",
                "02bda8ab73196ca246ba66ba9740f7d3552eb8b3dc6432e9c10d6f20f5f6c7e5fe",
                "02f5dbaa79265835cf344907ce73f497654516a9765a9817e36c83dd9f5f258ff7",
                "02ea57d9adbdbaf9d74631bc8e5004bc2b97fc06a77038c47efe3a377f0b42cbd0"
        };
        String[] expectedHashes = {
                "372047476748f85d8e90e927553e1d7b483a12861948626ec91855307fcb6bda",
                "bef7406739badddf9874e62507908b9c004345c3d98a04eab5c335326380ffdb",
                "c03ff629530efd10f6aed0d488d828b05c2517ccc88b5e1441e9f34526bf143a",
                "c03ff629530efd10f6aed0d488d828b05c2517ccc88b5e1441e9f34526bf143a",
                "11df6b170bf3ce2d663f6c38f030653c86d43eb64ef921c95b982346b8f1f614"
        };
        for(int i = 0; i < slots.size(); i++) {
            assertEquals(expectedKeys[i], Utils.bytesToHex(slots.get(i).getSignerPublicKey()));
            assertEquals(expectedHashes[i], Utils.bytesToHex(slots.get(i).getMessageHash()));
            assertEquals(AntiExfilCodec.SIGHASH_ALL, slots.get(i).getSighashType());
        }
    }

    @Test
    void reconstructsOnlyVerifiedSignaturesFromFrozenOriginal() {
        List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(raw, keystore);
        Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = deterministicRhos(slots);
        AntiExfilMessage commit = AntiExfilCodec.decode(Utils.hexToBytes(field("message_1_hex")));
        AntiExfilMessage signatures = AntiExfilCodec.decode(Utils.hexToBytes(field("message_4_hex")));
        byte[] signed = AntiExfilPsbt.reconstructSignedPsbt(raw, keystore, commit, signatures, rhos);
        assertEquals(field("signed_psbt_sha256"), Utils.bytesToHex(Sha256Hash.hash(signed)));
        PSBT parsed = AntiExfilPsbt.parseCanonicalV0(signed);
        assertEquals(5, parsed.getPsbtInputs().stream().mapToInt(input -> input.getPartialSignatures().size()).sum());
        assertArrayEquals(raw, AntiExfilPsbt.parseCanonicalV0(raw).serialize());

        List<AntiExfilSlot> incomplete = new ArrayList<>(signatures.getSlots());
        incomplete.removeLast();
        AntiExfilMessage truncated = new AntiExfilMessage(signatures.getNetwork(), signatures.getStage(),
                signatures.getSessionId(), signatures.getPsbtDigest(), incomplete);
        assertThrows(AntiExfilException.class,
                () -> AntiExfilPsbt.reconstructSignedPsbt(raw, keystore, commit, truncated, rhos));

        Map<AntiExfilSigningSlot.Identifier, byte[]> extra = new LinkedHashMap<>(rhos);
        extra.put(new AntiExfilSigningSlot.Identifier(99, ECKey.fromPrivate(BigInteger.valueOf(99)).getPubKey()), repeat((byte)99));
        assertThrows(AntiExfilException.class,
                () -> AntiExfilPsbt.reconstructSignedPsbt(raw, keystore, commit, signatures, extra));
    }

    @Test
    void rejectsNonCanonicalAndNonV0Psbts() {
        assertThrows(AntiExfilException.class, () -> AntiExfilPsbt.parseCanonicalV0(Arrays.copyOf(raw, raw.length - 1)));
        byte[] trailing = Arrays.copyOf(raw, raw.length + 1);
        trailing[trailing.length - 1] = 1;
        assertThrows(AntiExfilException.class, () -> AntiExfilPsbt.parseCanonicalV0(trailing));
        assertThrows(AntiExfilException.class, () -> AntiExfilPsbt.parseCanonicalV0("not-a-psbt".getBytes(StandardCharsets.US_ASCII)));
        PSBT v2 = AntiExfilPsbt.parseCanonicalV0(raw);
        v2.convertVersion(2);
        assertThrows(AntiExfilException.class, () -> AntiExfilPsbt.parseCanonicalV0(v2.serialize()));
    }

    @Test
    void rejectsUtxoScriptAndSighashMutations() {
        assertRejected(psbt -> psbt.getPsbtInputs().get(0).setWitnessUtxo(null));
        assertRejected(psbt -> psbt.getPsbtInputs().get(1).setRedeemScript(null));
        assertRejected(psbt -> psbt.getPsbtInputs().get(2).setWitnessScript(new Script(new byte[]{0x51})));
        assertRejected(psbt -> psbt.getPsbtInputs().get(0).setSigHash(SigHash.NONE));
        assertRejected(psbt -> psbt.getPsbtInputs().get(0).setSigHash(SigHash.ANYONECANPAY_ALL));
    }

    @Test
    void rejectsWrongAndForeignDerivationsAndExistingSignature() {
        assertRejected(psbt -> {
            PSBTInput input = psbt.getPsbtInputs().get(0);
            ECKey key = input.getDerivedPublicKeys().keySet().iterator().next();
            input.getDerivedPublicKeys().put(key, new KeyDerivation(keystore.getKeyDerivation().getMasterFingerprint(), "m/0"));
        });
        assertRejected(psbt -> {
            PSBTInput first = psbt.getPsbtInputs().get(0);
            Map.Entry<ECKey, KeyDerivation> entry = first.getDerivedPublicKeys().entrySet().iterator().next();
            psbt.getPsbtInputs().get(1).getDerivedPublicKeys().put(entry.getKey(), entry.getValue());
        });
        assertRejected(psbt -> {
            PSBTInput input = psbt.getPsbtInputs().get(0);
            ECKey key = input.getDerivedPublicKeys().keySet().iterator().next();
            input.getPartialSignatures().put(key,
                    new TransactionSignature(BigInteger.ONE, BigInteger.ONE, TransactionSignature.Type.ECDSA));
        });
    }

    @Test
    void rejectsTaprootAndMixedLegacyInputsAtomically() {
        ECKey key = ECKey.fromPrivate(BigInteger.valueOf(17));
        assertRejected(psbt -> psbt.getPsbtInputs().get(3).setWitnessUtxo(
                new TransactionOutput(null, 103_000, ScriptType.P2TR.getOutputScript(key.getPubKeyXCoord()))));
        assertRejected(psbt -> psbt.getPsbtInputs().get(3).setWitnessUtxo(
                new TransactionOutput(null, 103_000, ScriptType.P2PKH.getOutputScript(key.getPubKeyHash()))));
    }

    @Test
    void requiresExactUniqueRandomnessSet() {
        List<AntiExfilSigningSlot> slots = AntiExfilPsbt.enumerateSigningSlots(raw, keystore);
        Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = deterministicRhos(slots);
        AntiExfilMessage message = AntiExfilPsbt.buildHostCommitMessage(raw, keystore, AntiExfilNetwork.TESTNET4,
                repeat((byte)'z'), rhos);
        assertArrayEquals(Utils.hexToBytes(field("message_1_hex")), AntiExfilCodec.encode(message));

        Map<AntiExfilSigningSlot.Identifier, byte[]> incomplete = new LinkedHashMap<>(rhos);
        incomplete.remove(slots.getLast().getIdentifier());
        assertThrows(AntiExfilException.class, () -> AntiExfilPsbt.buildHostCommitMessage(
                raw, keystore, AntiExfilNetwork.TESTNET4, repeat((byte)'z'), incomplete));

        Map<AntiExfilSigningSlot.Identifier, byte[]> duplicate = new LinkedHashMap<>(rhos);
        duplicate.put(slots.getLast().getIdentifier(), rhos.get(slots.getFirst().getIdentifier()));
        assertThrows(AntiExfilException.class, () -> AntiExfilPsbt.buildHostCommitMessage(
                raw, keystore, AntiExfilNetwork.TESTNET4, repeat((byte)'z'), duplicate));
    }

    private void assertRejected(java.util.function.Consumer<PSBT> mutation) {
        PSBT psbt = AntiExfilPsbt.parseCanonicalV0(raw);
        mutation.accept(psbt);
        byte[] changed = psbt.serialize();
        assertThrows(AntiExfilException.class, () -> AntiExfilPsbt.enumerateSigningSlots(changed, keystore));
    }

    private static Map<AntiExfilSigningSlot.Identifier, byte[]> deterministicRhos(List<AntiExfilSigningSlot> slots) {
        Map<AntiExfilSigningSlot.Identifier, byte[]> rhos = new LinkedHashMap<>();
        for(int i = 0; i < slots.size(); i++) rhos.put(slots.get(i).getIdentifier(), repeat((byte)(0x80 + i)));
        return rhos;
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
}
