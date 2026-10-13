package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class AntiExfilCodecTest {
    private static final Pattern MESSAGE_HEX = Pattern.compile("\\\"message_hex\\\": \\\"([0-9a-f]+)\\\"");

    @Test
    void decodesAndReencodesFrozenMessages() throws IOException {
        List<byte[]> vectors = loadMessageVectors();
        assertEquals(4, vectors.size());
        for(int i = 0; i < vectors.size(); i++) {
            AntiExfilMessage message = AntiExfilCodec.decode(vectors.get(i));
            assertEquals(i + 1, message.getStage().getCode());
            assertEquals(AntiExfilNetwork.TESTNET4, message.getNetwork());
            assertEquals(3, message.getSlots().size());
            assertArrayEquals(vectors.get(i), AntiExfilCodec.encode(message));
        }
    }

    @Test
    void validatesFrozenTranscriptAndAllS2cSignatures() throws IOException {
        List<AntiExfilMessage> messages = loadMessageVectors().stream().map(AntiExfilCodec::decode).toList();
        for(int i = 1; i < messages.size(); i++) {
            AntiExfilCodec.validateTransition(messages.get(i - 1), messages.get(i));
        }

        AntiExfilMessage reveals = messages.get(2);
        AntiExfilMessage signatures = messages.get(3);
        for(int i = 0; i < signatures.getSlots().size(); i++) {
            AntiExfilSlot reveal = reveals.getSlots().get(i);
            AntiExfilSlot signature = signatures.getSlots().get(i);
            assertTrue(AntiExfilCrypto.verify(signature.getSignerPublicKey(), signature.getMessageHash(),
                    reveal.getHostRandomness(), signature.getOpening(), signature.getSignature()));
        }
    }

    @Test
    void rejectsNonCanonicalAndSubstitutedMessages() throws IOException {
        byte[] encoded = loadMessageVectors().getFirst();
        byte[] badFlags = encoded.clone();
        badFlags[7] = 1;
        assertEquals(AntiExfilException.Code.INVALID_MESSAGE,
                assertThrows(AntiExfilException.class, () -> AntiExfilCodec.decode(badFlags)).getCode());

        AntiExfilMessage commit = AntiExfilCodec.decode(encoded);
        List<AntiExfilSlot> reversed = new ArrayList<>(commit.getSlots());
        java.util.Collections.reverse(reversed);
        AntiExfilMessage unordered = new AntiExfilMessage(commit.getNetwork(), commit.getStage(),
                commit.getSessionId(), commit.getPsbtDigest(), reversed);
        assertEquals(AntiExfilException.Code.SIGNATURE_SLOT_MISMATCH,
                assertThrows(AntiExfilException.class, () -> AntiExfilCodec.encode(unordered)).getCode());

        AntiExfilMessage openings = AntiExfilCodec.decode(loadMessageVectors().get(1));
        byte[] changedSession = openings.getSessionId();
        changedSession[0] ^= 1;
        AntiExfilMessage substituted = new AntiExfilMessage(openings.getNetwork(), openings.getStage(),
                changedSession, openings.getPsbtDigest(), openings.getSlots());
        assertEquals(AntiExfilException.Code.SESSION_MISMATCH,
                assertThrows(AntiExfilException.class, () -> AntiExfilCodec.validateTransition(commit, substituted)).getCode());
    }

    @Test
    void commitmentUsesPinnedTaggedHash() throws IOException {
        AntiExfilMessage commit = AntiExfilCodec.decode(loadMessageVectors().getFirst());
        byte[][] rhos = {repeat((byte)0xa1), repeat((byte)0xa3), repeat((byte)0xa2)};
        for(int i = 0; i < rhos.length; i++) {
            assertArrayEquals(commit.getSlots().get(i).getCommitment(), AntiExfilCrypto.hostCommit(rhos[i]));
        }
    }

    @Test
    void transitionValidationFullyValidatesBothObjectEndpoints() throws IOException {
        List<AntiExfilMessage> messages = loadMessageVectors().stream().map(AntiExfilCodec::decode).toList();
        AntiExfilMessage commit = messages.get(0);
        AntiExfilMessage openings = messages.get(1);
        AntiExfilMessage malformedPrevious = new AntiExfilMessage(commit.getNetwork(), commit.getStage(), null,
                commit.getPsbtDigest(), commit.getSlots());
        AntiExfilMessage malformedCurrent = new AntiExfilMessage(openings.getNetwork(), openings.getStage(),
                openings.getSessionId(), openings.getPsbtDigest(), null);

        assertEquals(AntiExfilException.Code.INVALID_MESSAGE,
                assertThrows(AntiExfilException.class,
                        () -> AntiExfilCodec.validateTransition(malformedPrevious, openings)).getCode());
        assertEquals(AntiExfilException.Code.INVALID_MESSAGE,
                assertThrows(AntiExfilException.class,
                        () -> AntiExfilCodec.validateTransition(commit, malformedCurrent)).getCode());
        assertEquals(AntiExfilException.Code.INVALID_MESSAGE,
                assertThrows(AntiExfilException.class,
                        () -> AntiExfilCodec.validateTransition(null, openings)).getCode());
        assertDoesNotThrow(() -> AntiExfilCodec.validateTransition(commit, openings));
    }

    @Test
    @SuppressWarnings("deprecation")
    void publicMagicMutationCannotChangeCanonicalFraming() throws IOException {
        byte[] canonical = loadMessageVectors().getFirst();
        byte original = AntiExfilCodec.MAGIC[0];
        try {
            AntiExfilCodec.MAGIC[0] ^= 0x20;
            AntiExfilMessage decoded = assertDoesNotThrow(() -> AntiExfilCodec.decode(canonical));
            assertArrayEquals(canonical, AntiExfilCodec.encode(decoded));
            assertArrayEquals(new byte[]{'A', 'E', 'X', 'B'},
                    Arrays.copyOf(AntiExfilCodec.encode(decoded), 4));
        } finally {
            AntiExfilCodec.MAGIC[0] = original;
        }
    }

    @Test
    void openingsMustBeUniqueAcrossTheSlotSet() throws IOException {
        AntiExfilMessage openings = AntiExfilCodec.decode(loadMessageVectors().get(1));
        AntiExfilSlot first = openings.getSlots().get(0);
        AntiExfilSlot second = openings.getSlots().get(1);

        AntiExfilSlot repeatedForSameKey = copySlot(second, first.getSignerPublicKey(), first.getOpening());
        List<AntiExfilSlot> repeatedSlots = sortedSlots(first, repeatedForSameKey, openings.getSlots().get(2));
        AntiExfilMessage repeated = copyMessage(openings, repeatedSlots);
        assertEquals(AntiExfilException.Code.OPENING_MISMATCH,
                assertThrows(AntiExfilException.class, () -> AntiExfilCodec.encode(repeated)).getCode());

        AntiExfilSlot distinctForSameKey = copySlot(second, first.getSignerPublicKey(), second.getOpening());
        assertDoesNotThrow(() -> AntiExfilCodec.encode(copyMessage(openings,
                sortedSlots(first, distinctForSameKey, openings.getSlots().get(2)))));

        //Reuse under two sibling keys of the same account xpub is the same key-recovery algebra as same-key reuse.
        AntiExfilSlot repeatedAcrossDifferentKeys = copySlot(second, second.getSignerPublicKey(), first.getOpening());
        assertFalse(Arrays.equals(first.getSignerPublicKey(), repeatedAcrossDifferentKeys.getSignerPublicKey()));
        AntiExfilMessage repeatedAcrossKeys = copyMessage(openings,
                sortedSlots(first, repeatedAcrossDifferentKeys, openings.getSlots().get(2)));
        assertEquals(AntiExfilException.Code.OPENING_MISMATCH,
                assertThrows(AntiExfilException.class, () -> AntiExfilCodec.encode(repeatedAcrossKeys)).getCode());
    }

    @Test
    void rejectsNegatedOpeningUnderADifferentKey() throws IOException {
        //R and -R share an x-coordinate, so a comparison on the compressed point alone misses the negated equivalent.
        AntiExfilMessage openings = AntiExfilCodec.decode(loadMessageVectors().get(1));
        AntiExfilSlot first = openings.getSlots().get(0);
        AntiExfilSlot second = openings.getSlots().get(1);
        byte[] negated = first.getOpening().clone();
        negated[0] ^= 0x01; //0x02 <-> 0x03
        assertFalse(Arrays.equals(first.getOpening(), negated));
        assertFalse(Arrays.equals(first.getSignerPublicKey(), second.getSignerPublicKey()));

        AntiExfilSlot negatedSlot = copySlot(second, second.getSignerPublicKey(), negated);
        AntiExfilMessage message = copyMessage(openings,
                sortedSlots(first, negatedSlot, openings.getSlots().get(2)));
        assertEquals(AntiExfilException.Code.OPENING_MISMATCH,
                assertThrows(AntiExfilException.class, () -> AntiExfilCodec.encode(message)).getCode());
    }

    @Test
    void rejectsSharedHostNegativeVectors() throws IOException {
        try(InputStream stream = AntiExfilCodecTest.class.getResourceAsStream("protocol-v1-negative-vectors.json")) {
            assertNotNull(stream);
            String vector = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            Matcher matcher = MESSAGE_HEX.matcher(vector);
            assertTrue(matcher.find());
            byte[] encoded = Utils.hexToBytes(matcher.group(1));
            AntiExfilException exception = assertThrows(AntiExfilException.class,
                    () -> AntiExfilCodec.decode(encoded));
            assertEquals(AntiExfilException.Code.OPENING_MISMATCH, exception.getCode());
            assertFalse(matcher.find());
        }
    }

    private static AntiExfilMessage copyMessage(AntiExfilMessage message, List<AntiExfilSlot> slots) {
        return new AntiExfilMessage(message.getNetwork(), message.getStage(), message.getSessionId(),
                message.getPsbtDigest(), slots);
    }

    private static AntiExfilSlot copySlot(AntiExfilSlot slot, byte[] signerPublicKey, byte[] opening) {
        return new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), signerPublicKey,
                slot.getMessageHash(), slot.getCommitment(), opening, slot.getHostRandomness(), slot.getSignature());
    }

    private static List<AntiExfilSlot> sortedSlots(AntiExfilSlot... slots) {
        List<AntiExfilSlot> sorted = new ArrayList<>(List.of(slots));
        sorted.sort(Comparator.comparingLong(AntiExfilSlot::getInputIndex)
                .thenComparing(AntiExfilSlot::getSignerPublicKey, Arrays::compareUnsigned));
        return sorted;
    }

    private static byte[] repeat(byte value) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, value);
        return bytes;
    }

    private static List<byte[]> loadMessageVectors() throws IOException {
        try(InputStream stream = AntiExfilCodecTest.class.getResourceAsStream("protocol-v1-multislot-vectors.json")) {
            assertNotNull(stream);
            Matcher matcher = MESSAGE_HEX.matcher(new String(stream.readAllBytes(), StandardCharsets.UTF_8));
            List<byte[]> vectors = new ArrayList<>();
            while(matcher.find()) {
                vectors.add(Utils.hexToBytes(matcher.group(1)));
            }
            return vectors;
        }
    }
}
