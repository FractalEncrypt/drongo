package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
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
        assertEquals(AntiExfilException.Code.TRANSACTION_MISMATCH,
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
