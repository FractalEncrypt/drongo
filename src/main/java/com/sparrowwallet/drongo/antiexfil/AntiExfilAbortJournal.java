package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class AntiExfilAbortJournal {
    private static final byte[] MAGIC = {'A', 'E', 'X', 'J'};
    private static final int VERSION = 1;
    private static final int MAX_FILE_BYTES = 4 * 1024 * 1024;
    private static final int MAX_EVENTS = 10_000;
    private static final int MAX_REASON_BYTES = 512;

    private final Path path;
    private final byte[] walletIdentity;

    public AntiExfilAbortJournal(Path path, byte[] walletIdentity) {
        if(path == null || walletIdentity == null || walletIdentity.length != 32) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort-journal identity");
        }
        this.path = AntiExfilDurableFiles.canonicalPath(path);
        this.walletIdentity = walletIdentity.clone();
    }

    public List<AbortEvent> getEvents() {
        return locked(LockedJournal::getEvents);
    }

    AbortEvent append(byte[] sessionId, byte[] psbtDigest, String reason) {
        String normalizedReason = validateEvent(sessionId, psbtDigest, reason);
        return locked(journal -> journal.append(sessionId, psbtDigest, normalizedReason));
    }

    <T> T locked(LockedAction<T> action) {
        return AntiExfilDurableFiles.locked(path, () -> action.run(new LockedJournal(loadOrCreate())));
    }

    private static String validateEvent(byte[] sessionId, byte[] psbtDigest, String reason) {
        if(sessionId == null || sessionId.length != 32 || psbtDigest == null || psbtDigest.length != 32) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID, "Invalid abort event context");
        }
        byte[] reasonBytes = reason == null ? new byte[0] : reason.strip().getBytes(StandardCharsets.UTF_8);
        if(reasonBytes.length == 0 || reasonBytes.length > MAX_REASON_BYTES) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                    "Abort reason must contain 1 to " + MAX_REASON_BYTES + " UTF-8 bytes");
        }
        return new String(reasonBytes, StandardCharsets.UTF_8);
    }

    private Journal loadOrCreate() throws IOException {
        if(!Files.exists(path)) {
            Journal journal = new Journal(walletIdentity, List.of());
            AntiExfilDurableFiles.write(path, encode(journal), true, MAX_FILE_BYTES);
            return journal;
        }
        Journal journal = decode(AntiExfilDurableFiles.read(path, MAX_FILE_BYTES));
        if(!Arrays.equals(walletIdentity, journal.walletIdentity)) throw new IOException("Abort journal belongs to another wallet key identity");
        return journal;
    }

    private static byte[] encode(Journal journal) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try(DataOutputStream output = new DataOutputStream(bytes)) {
            output.write(MAGIC);
            output.writeByte(VERSION);
            output.write(journal.walletIdentity);
            output.writeInt(journal.events.size());
            for(AbortEvent event : journal.events) {
                byte[] reason = event.reason.getBytes(StandardCharsets.UTF_8);
                output.write(event.sessionId);
                output.write(event.psbtDigest);
                output.writeLong(event.recordedAtEpochSecond);
                output.writeShort(reason.length);
                output.write(reason);
            }
        }
        return bytes.toByteArray();
    }

    private static Journal decode(byte[] body) throws IOException {
        try(DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
            byte[] magic = input.readNBytes(4);
            if(!Arrays.equals(magic, MAGIC) || input.readUnsignedByte() != VERSION) throw new IOException("Unknown abort-journal format");
            byte[] identity = input.readNBytes(32);
            int count = input.readInt();
            if(identity.length != 32 || count < 0 || count > MAX_EVENTS) throw new IOException("Invalid abort-journal header");
            List<AbortEvent> events = new ArrayList<>(count);
            for(int i = 0; i < count; i++) {
                byte[] sessionId = input.readNBytes(32);
                byte[] digest = input.readNBytes(32);
                long timestamp = input.readLong();
                int reasonLength = input.readUnsignedShort();
                byte[] reason = input.readNBytes(reasonLength);
                if(sessionId.length != 32 || digest.length != 32 || reasonLength < 1
                        || reasonLength > MAX_REASON_BYTES || reason.length != reasonLength || timestamp < 0) {
                    throw new IOException("Invalid abort-journal event");
                }
                events.add(new AbortEvent(sessionId, digest, timestamp, new String(reason, StandardCharsets.UTF_8)));
            }
            if(input.available() != 0) throw new IOException("Trailing abort-journal data");
            return new Journal(identity, events);
        } catch(EOFException e) {
            throw new IOException("Truncated abort journal", e);
        }
    }

    public static final class AbortEvent {
        private final byte[] sessionId;
        private final byte[] psbtDigest;
        private final long recordedAtEpochSecond;
        private final String reason;

        private AbortEvent(byte[] sessionId, byte[] psbtDigest, long recordedAtEpochSecond, String reason) {
            this.sessionId = sessionId.clone();
            this.psbtDigest = psbtDigest.clone();
            this.recordedAtEpochSecond = recordedAtEpochSecond;
            this.reason = reason;
        }

        public byte[] getSessionId() { return sessionId.clone(); }
        public byte[] getPsbtDigest() { return psbtDigest.clone(); }
        public long getRecordedAtEpochSecond() { return recordedAtEpochSecond; }
        public String getReason() { return reason; }
    }

    final class LockedJournal {
        private Journal journal;

        private LockedJournal(Journal loaded) {
            List<AbortEvent> unique = new ArrayList<>();
            for(AbortEvent candidate : loaded.events) {
                if(findBySession(unique, candidate.sessionId) == null) unique.add(candidate);
            }
            this.journal = new Journal(loaded.walletIdentity, unique);
        }

        List<AbortEvent> getEvents() {
            return List.copyOf(journal.events);
        }

        byte[] getDigest() throws IOException {
            return Sha256Hash.hash(encode(journal));
        }

        AbortEvent append(byte[] sessionId, byte[] psbtDigest, String reason) throws IOException {
            String normalizedReason = validateEvent(sessionId, psbtDigest, reason);
            AbortEvent existing = findBySession(journal.events, sessionId);
            if(existing != null) return existing;
            if(journal.events.size() >= MAX_EVENTS) throw new IOException("Abort journal is full");
            AbortEvent event = new AbortEvent(sessionId, psbtDigest, Instant.now().getEpochSecond(), normalizedReason);
            List<AbortEvent> updated = new ArrayList<>(journal.events);
            updated.add(event);
            journal = new Journal(walletIdentity, updated);
            AntiExfilDurableFiles.write(path, encode(journal), false, MAX_FILE_BYTES);
            return event;
        }
    }

    private static AbortEvent findBySession(List<AbortEvent> events, byte[] sessionId) {
        for(AbortEvent event : events) {
            if(Arrays.equals(event.sessionId, sessionId)) return event;
        }
        return null;
    }

    @FunctionalInterface
    interface LockedAction<T> {
        T run(LockedJournal journal) throws IOException;
    }

    private record Journal(byte[] walletIdentity, List<AbortEvent> events) {
    }
}
