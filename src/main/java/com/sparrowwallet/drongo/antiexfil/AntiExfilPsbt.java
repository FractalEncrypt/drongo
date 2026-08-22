package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptChunk;
import com.sparrowwallet.drongo.protocol.ScriptOpCodes;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTParseException;
import com.sparrowwallet.drongo.wallet.Keystore;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;

public final class AntiExfilPsbt {
    private AntiExfilPsbt() {
    }

    public static PSBT parseCanonicalV0(byte[] raw) {
        if(raw == null || raw.length < 5 || raw[0] != 'p' || raw[1] != 's' || raw[2] != 'b' || raw[3] != 't' || raw[4] != (byte)0xff) {
            throw fail(INVALID_MESSAGE, "Invalid PSBT magic");
        }
        try {
            // Valid foreign multisig partials are preserved, but an invalid one would consume
            // a protected ceremony only to produce a PSBT that downstream combine rejects.
            PSBT psbt = new PSBT(raw, true);
            if(psbt.getVersion() != null && psbt.getVersion() != 0) {
                throw fail(INVALID_MESSAGE, "Protocol v1 accepts PSBT v0 only");
            }
            if(!Arrays.equals(raw, psbt.serialize())) {
                throw fail(INVALID_MESSAGE, "PSBT is not canonically encoded");
            }
            if(psbt.getTransaction() == null || psbt.getPsbtInputs().isEmpty() || psbt.getPsbtOutputs().isEmpty()) {
                throw fail(INVALID_MESSAGE, "PSBT requires an unsigned transaction");
            }
            return psbt;
        } catch(PSBTParseException | RuntimeException e) {
            if(e instanceof AntiExfilException antiExfilException) throw antiExfilException;
            throw new AntiExfilException(INVALID_MESSAGE, "Invalid PSBT: " + e.getMessage(), e);
        }
    }

    public static List<AntiExfilSigningSlot> enumerateSigningSlots(byte[] raw, Keystore keystore) {
        if(keystore == null || keystore.getKeyDerivation() == null || keystore.getExtendedPublicKey() == null) {
            throw fail(INVALID_MESSAGE, "A public account keystore is required");
        }
        PSBT psbt = parseCanonicalV0(raw);
        List<AntiExfilSigningSlot> slots = new ArrayList<>();
        for(int index = 0; index < psbt.getPsbtInputs().size(); index++) {
            PSBTInput input = psbt.getPsbtInputs().get(index);
            failOnTaproot(index, input);
            if(input.getUtxo() == null) failInput(index, "missing UTXO data");
            ScriptClassification classification = classify(index, input);
            SigHash sigHash = input.getSigHash() == null ? SigHash.ALL : input.getSigHash();
            if(sigHash != SigHash.ALL) failInput(index, "protocol v1 supports only explicit SIGHASH_ALL");
            validateDerivations(index, input, classification.signingKeys());
            byte[] messageHash;
            try {
                messageHash = input.getSigningHash().getBytes();
            } catch(RuntimeException e) {
                throw new AntiExfilException(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": cannot derive sighash", e);
            }
            for(Map.Entry<ECKey, KeyDerivation> entry : input.getDerivedPublicKeys().entrySet()) {
                ECKey publicKey = entry.getKey();
                KeyDerivation derivation = entry.getValue();
                if(!classification.signingKeys().contains(publicKey)
                        || !keystore.getKeyDerivation().getMasterFingerprint().equals(derivation.getMasterFingerprint())) continue;
                ECKey expected = keystore.getPubKeyForDerivation(derivation);
                if(expected == null || !Arrays.equals(expected.getPubKey(), publicKey.getPubKey())) {
                    failInput(index, "BIP32 path does not derive its declared public key");
                }
                if(input.getPartialSignatures().containsKey(publicKey)) {
                    throw fail(UNEXPECTED_RETURN_DATA, "Input " + index + " already has a controlled signature");
                }
                if(input.isFinalized()) {
                    throw fail(UNEXPECTED_RETURN_DATA,
                            "Input " + index + " is finalized for a controlled key");
                }
                slots.add(new AntiExfilSigningSlot(index, publicKey.getPubKey(), messageHash,
                        AntiExfilCodec.SIGHASH_ALL, derivation, classification.kind()));
            }
        }
        slots.sort((left, right) -> left.getIdentifier().compareTo(right.getIdentifier()));
        if(slots.isEmpty()) throw fail(SIGNATURE_SLOT_MISMATCH, "PSBT has no controlled signing slots");
        if(slots.size() > AntiExfilCodec.MAX_SLOTS) throw fail(SIGNATURE_SLOT_MISMATCH, "PSBT exceeds the global slot limit");
        Set<AntiExfilSigningSlot.Identifier> identifiers = new HashSet<>();
        Map<Integer, Integer> perInput = new LinkedHashMap<>();
        for(AntiExfilSigningSlot slot : slots) {
            if(!identifiers.add(slot.getIdentifier())) throw fail(SIGNATURE_SLOT_MISMATCH, "Duplicate signing slot");
            int count = perInput.merge(slot.getInputIndex(), 1, Integer::sum);
            if(count > AntiExfilCodec.MAX_SLOTS_PER_INPUT) failInput(slot.getInputIndex(), "input exceeds the per-input slot limit");
        }
        return List.copyOf(slots);
    }

    public static AntiExfilMessage buildHostCommitMessage(byte[] raw, Keystore keystore, AntiExfilNetwork network,
                                                           byte[] sessionId,
                                                           Map<AntiExfilSigningSlot.Identifier, byte[]> hostRandomness) {
        List<AntiExfilSigningSlot> semantic = enumerateSigningSlots(raw, keystore);
        Set<AntiExfilSigningSlot.Identifier> expected = new HashSet<>();
        semantic.forEach(slot -> expected.add(slot.getIdentifier()));
        if(hostRandomness == null || !hostRandomness.keySet().equals(expected)) {
            throw fail(SIGNATURE_SLOT_MISMATCH, "Host randomness must cover the exact slot set");
        }
        Set<ByteArray> uniqueRandomness = new HashSet<>();
        List<AntiExfilSlot> records = new ArrayList<>();
        for(AntiExfilSigningSlot slot : semantic) {
            byte[] rho = hostRandomness.get(slot.getIdentifier());
            if(rho == null || rho.length != 32 || !uniqueRandomness.add(new ByteArray(rho))) {
                throw fail(COMMITMENT_MISMATCH, "Host randomness must be valid and unique per slot");
            }
            records.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(),
                    slot.getMessageHash(), AntiExfilCrypto.hostCommit(rho), null, null, null));
        }
        AntiExfilMessage message = new AntiExfilMessage(network, AntiExfilStage.HOST_COMMIT, sessionId, Sha256Hash.hash(raw), records);
        AntiExfilCodec.validate(message);
        return message;
    }

    public static byte[] reconstructSignedPsbt(byte[] original, Keystore keystore, AntiExfilMessage commit,
                                               AntiExfilMessage openings, AntiExfilMessage reveal,
                                               AntiExfilMessage signatures,
                                               Map<AntiExfilSigningSlot.Identifier, byte[]> hostRandomness) {
        List<AntiExfilSigningSlot> semantic = enumerateSigningSlots(original, keystore);
        Set<AntiExfilSigningSlot.Identifier> expectedIdentifiers = new HashSet<>();
        semantic.forEach(slot -> expectedIdentifiers.add(slot.getIdentifier()));
        if(hostRandomness == null || !hostRandomness.keySet().equals(expectedIdentifiers)) {
            throw fail(SIGNATURE_SLOT_MISMATCH, "Stored host randomness differs from the authoritative slot set");
        }
        AntiExfilCodec.validate(commit);
        AntiExfilCodec.validate(openings);
        AntiExfilCodec.validate(reveal);
        AntiExfilCodec.validate(signatures);
        if(commit == null || commit.getStage() != AntiExfilStage.HOST_COMMIT
                || !Arrays.equals(commit.getPsbtDigest(), Sha256Hash.hash(original))
                || commit.getSlots().size() != semantic.size()) {
            throw fail(TRANSACTION_MISMATCH, "Commit message is not authoritative for the PSBT");
        }
        if(signatures == null || signatures.getStage() != AntiExfilStage.SIGNER_SIGNATURES) {
            throw fail(WRONG_STAGE, "Expected signer-signatures message");
        }
        AntiExfilCodec.validateTransition(commit, openings);
        AntiExfilCodec.validateTransition(openings, reveal);
        AntiExfilCodec.validateTransition(reveal, signatures);
        if(signatures.getSlots().size() != semantic.size()) throw fail(TRANSACTION_MISMATCH, "Signature response context changed");
        PSBT reconstructed = parseCanonicalV0(original);
        for(int i = 0; i < semantic.size(); i++) {
            AntiExfilSigningSlot authoritative = semantic.get(i);
            AntiExfilSlot before = commit.getSlots().get(i);
            AntiExfilSlot revealed = reveal.getSlots().get(i);
            AntiExfilSlot after = signatures.getSlots().get(i);
            byte[] rho = hostRandomness == null ? null : hostRandomness.get(authoritative.getIdentifier());
            requireSlot(authoritative, before);
            requireSlot(authoritative, after);
            if(rho == null || !Arrays.equals(rho, revealed.getHostRandomness())
                    || !Arrays.equals(AntiExfilCrypto.hostCommit(rho), before.getCommitment())) {
                throw fail(COMMITMENT_MISMATCH, "Stored randomness or response commitment changed");
            }
            if(!AntiExfilCrypto.verify(after.getSignerPublicKey(), after.getMessageHash(), rho,
                    after.getOpening(), after.getSignature())) {
                throw fail(SIGNATURE_INVALID, "Anti-exfil signature verification failed");
            }
            byte[] compact = after.getSignature();
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(compact, 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(compact, 32, 64));
            TransactionSignature signature = new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
            reconstructed.getPsbtInputs().get(authoritative.getInputIndex()).getPartialSignatures()
                    .put(ECKey.fromPublicOnly(authoritative.getSignerPublicKey()), signature);
        }
        return reconstructed.serialize();
    }

    private static void requireSlot(AntiExfilSigningSlot authoritative, AntiExfilSlot record) {
        if(record.getInputIndex() != Integer.toUnsignedLong(authoritative.getInputIndex())
                || record.getSighashType() != AntiExfilCodec.SIGHASH_ALL
                || !Arrays.equals(record.getSignerPublicKey(), authoritative.getSignerPublicKey())
                || !Arrays.equals(record.getMessageHash(), authoritative.getMessageHash())) {
            throw fail(SIGNATURE_SLOT_MISMATCH, "Protocol slot differs from authoritative PSBT semantics");
        }
    }

    private static ScriptClassification classify(int index, PSBTInput input) {
        ScriptType type = input.getScriptType();
        if(type == ScriptType.P2WPKH || type == ScriptType.P2SH_P2WPKH) {
            Script program = type == ScriptType.P2WPKH ? input.getUtxo().getScript() : input.getRedeemScript();
            if(program == null || !ScriptType.P2WPKH.isScriptType(program)) failInput(index, "inconsistent P2WPKH script");
            List<ECKey> matches = input.getDerivedPublicKeys().keySet().stream()
                    .filter(key -> ScriptType.P2WPKH.getOutputScript(key.getPubKeyHash()).equals(program)).toList();
            if(matches.size() != 1) failInput(index, "P2WPKH requires exactly one matching BIP32 public key");
            return new ScriptClassification(type == ScriptType.P2WPKH ? "p2wpkh" : "p2sh-p2wpkh", Set.copyOf(matches));
        }
        if(type == ScriptType.P2WSH || type == ScriptType.P2SH_P2WSH) {
            Script witnessScript = input.getWitnessScript();
            if(witnessScript == null || !ScriptType.MULTISIG.isScriptType(witnessScript)) failInput(index, "witness script is not standard multisig");
            List<ScriptChunk> chunks = witnessScript.getChunks();
            if(!chunks.getLast().equalsOpCode(ScriptOpCodes.OP_CHECKMULTISIG)) failInput(index, "witness script must end in CHECKMULTISIG");
            ECKey[] keys;
            try {
                keys = ScriptType.MULTISIG.getPublicKeysFromScript(witnessScript);
                if(ScriptType.MULTISIG.getThreshold(witnessScript) > keys.length) failInput(index, "multisig threshold exceeds key count");
                for(int i = 1; i < chunks.size() - 2; i++) {
                    if(chunks.get(i).getOpcode() != 33 || chunks.get(i).getData() == null || chunks.get(i).getData().length != 33) {
                        failInput(index, "multisig keys must use canonical compressed pushes");
                    }
                }
            } catch(RuntimeException e) {
                throw new AntiExfilException(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": invalid multisig script", e);
            }
            Set<ECKey> unique = new HashSet<>(Arrays.asList(keys));
            if(unique.size() != keys.length) failInput(index, "multisig public keys must be unique");
            String kind = type == ScriptType.P2WSH ? "p2wsh-multisig" : "p2sh-p2wsh-multisig";
            return new ScriptClassification(kind, Set.copyOf(unique));
        }
        failInput(index, "unsupported or inconsistent script type " + type);
        throw new AssertionError();
    }

    private static void validateDerivations(int index, PSBTInput input, Set<ECKey> signingKeys) {
        Set<ECKey> seen = new HashSet<>();
        for(Map.Entry<ECKey, KeyDerivation> entry : input.getDerivedPublicKeys().entrySet()) {
            if(!seen.add(entry.getKey()) || !signingKeys.contains(entry.getKey())
                    || entry.getValue() == null || entry.getValue().getMasterFingerprint() == null
                    || entry.getValue().getMasterFingerprint().length() != 8) {
                failInput(index, "invalid, duplicate, or script-foreign BIP32 derivation");
            }
        }
    }

    private static void failOnTaproot(int index, PSBTInput input) {
        if(input.isTaproot() || input.getTapInternalKey() != null || input.getTapKeyPathSignature() != null
                || !input.getTapDerivedPublicKeys().isEmpty()) failInput(index, "Taproot data is unsupported");
    }

    private static void failInput(int index, String message) {
        throw fail(SIGNATURE_SLOT_MISMATCH, "Input " + index + ": " + message);
    }

    private static AntiExfilException fail(AntiExfilException.Code code, String message) {
        return new AntiExfilException(code, message);
    }

    private record ScriptClassification(String kind, Set<ECKey> signingKeys) {}
    private record ByteArray(byte[] value) {
        @Override public boolean equals(Object object) { return object instanceof ByteArray other && Arrays.equals(value, other.value); }
        @Override public int hashCode() { return Arrays.hashCode(value); }
    }
}
