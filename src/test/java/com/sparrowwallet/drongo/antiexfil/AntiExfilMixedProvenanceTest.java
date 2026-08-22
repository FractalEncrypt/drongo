package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class AntiExfilMixedProvenanceTest {
    private static final Pattern STRING_FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

    @TempDir
    Path temporary;

    @Test
    void provesOnlyProtectedSignerWhilePreservingForeignOrdinarySignature() throws Exception {
        String vector;
        try(InputStream stream = getClass().getResourceAsStream("protocol-v1-mixed-provenance-vector.json")) {
            assertNotNull(stream);
            vector = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
        byte[] original = Utils.hexToBytes(field(vector, "original_psbt_hex"));
        byte[] message2 = Utils.hexToBytes(field(vector, "message_2_hex"));
        byte[] message4 = Utils.hexToBytes(field(vector, "message_4_hex"));
        DeterministicSeed seed = new DeterministicSeed(field(vector, "mnemonic"), "", 0, DeterministicSeed.Type.BIP39);
        Keystore signerA = Keystore.fromSeed(seed, PolicyType.MULTI_HD,
                KeyDerivation.parsePath(field(vector, "account_derivation")));
        signerA.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED);
        Path session = temporary.resolve("mixed.aexs");
        Path journal = temporary.resolve("mixed.aexj");

        AntiExfilCoordinator coordinator = AntiExfilCoordinator.create(session, journal, original, signerA,
                AntiExfilNetwork.TESTNET4, false, new MixedVectorRandom());
        assertArrayEquals(Utils.hexToBytes(field(vector, "message_1_hex")), coordinator.getHostCommitMessage());
        coordinator.acceptOpenings(message2);
        AntiExfilCoordinator.Completion completion = coordinator.complete(message4);

        assertArrayEquals(Utils.hexToBytes(field(vector, "signed_psbt_hex")), completion.getSignedPsbt());
        assertEquals(1, completion.getVerifiedSignatures().size());
        VerifiedAntiExfilSignature proof = completion.getVerifiedSignatures().iterator().next();
        assertArrayEquals(Utils.hexToBytes(field(vector, "protected_signature_a_compact")), proof.getCompactSignature());
        assertArrayEquals(Utils.hexToBytes(field(vector, "pubkey")), proof.getSignerPublicKey());

        PSBT signed = new PSBT(completion.getSignedPsbt(), false);
        assertEquals(2, signed.getPsbtInputs().getFirst().getPartialSignatures().size());
        long ordinaryMatches = signed.getPsbtInputs().getFirst().getPartialSignatures().values().stream()
                .map(TransactionSignature::encodeToBitcoin)
                .filter(signature -> Arrays.equals(signature, Utils.hexToBytes(field(vector, "ordinary_signature_der"))))
                .count();
        assertEquals(1, ordinaryMatches);
    }

    @Test
    void rejectsInvalidForeignPartialBeforeCreatingCoordinatorState() throws Exception {
        String vector;
        try(InputStream stream = getClass().getResourceAsStream("protocol-v1-mixed-provenance-vector.json")) {
            assertNotNull(stream);
            vector = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
        byte[] original = Utils.hexToBytes(field(vector, "original_psbt_hex"));
        PSBT doctored = new PSBT(original, false);
        ECKey foreignKey = doctored.getPsbtInputs().getFirst().getPartialSignatures().keySet().iterator().next();
        doctored.getPsbtInputs().getFirst().getPartialSignatures().put(foreignKey,
                new TransactionSignature(BigInteger.ONE, BigInteger.ONE, TransactionSignature.Type.ECDSA));
        byte[] invalid = doctored.serialize();

        DeterministicSeed seed = new DeterministicSeed(field(vector, "mnemonic"), "", 0,
                DeterministicSeed.Type.BIP39);
        Keystore signerA = Keystore.fromSeed(seed, PolicyType.MULTI_HD,
                KeyDerivation.parsePath(field(vector, "account_derivation")));
        signerA.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED);
        Path session = temporary.resolve("invalid-foreign.aexs");
        Path journal = temporary.resolve("invalid-foreign.aexj");

        AntiExfilException rejected = assertThrows(AntiExfilException.class,
                () -> AntiExfilCoordinator.create(session, journal, invalid, signerA,
                        AntiExfilNetwork.TESTNET4, false, new MixedVectorRandom()));
        assertEquals(AntiExfilException.Code.INVALID_MESSAGE, rejected.getCode());
        assertFalse(Files.exists(session));
        assertFalse(Files.exists(journal));
    }

    private static String field(String vector, String name) {
        Matcher matcher = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(name))).matcher(vector);
        assertTrue(matcher.find(), "Missing vector field " + name);
        return matcher.group(1);
    }

    private static final class MixedVectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'m' : (byte)0xa1);
        }
    }
}
