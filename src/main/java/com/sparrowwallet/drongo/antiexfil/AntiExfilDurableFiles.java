package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.EnumSet;

import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;

final class AntiExfilDurableFiles {
    private AntiExfilDurableFiles() {
    }

    static <T> T locked(Path target, IOAction<T> action) {
        try {
            Path absolute = target.toAbsolutePath();
            Path parent = absolute.getParent();
            if(parent == null) throw new IOException("Durable state requires a parent directory");
            Files.createDirectories(parent);
            Path lockPath = parent.resolve(absolute.getFileName() + ".lock");
            try(FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                FileLock ignored = channel.lock()) {
                return action.run();
            }
        } catch(IOException e) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                    "Cannot access durable anti-exfil state: " + e.getMessage(), e);
        }
    }

    static byte[] read(Path path, int maximumBytes) throws IOException {
        byte[] encoded = Files.readAllBytes(path);
        if(encoded.length < 32 || encoded.length > maximumBytes) throw new IOException("State length is outside limits");
        byte[] body = Arrays.copyOf(encoded, encoded.length - 32);
        byte[] checksum = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        if(!Arrays.equals(Sha256Hash.hash(body), checksum)) throw new IOException("State checksum mismatch");
        return body;
    }

    static void write(Path path, byte[] body, boolean createOnly) throws IOException {
        if(createOnly && Files.exists(path)) throw new IOException("State already exists");
        byte[] encoded = ByteBuffer.allocate(body.length + 32).put(body).put(Sha256Hash.hash(body)).array();
        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        Path temporary = Files.createTempFile(parent, absolute.getFileName() + ".", ".tmp");
        boolean moved = false;
        try {
            try {
                Files.setPosixFilePermissions(temporary, EnumSet.of(OWNER_READ, OWNER_WRITE));
            } catch(UnsupportedOperationException ignored) {
                // Windows uses inherited ACLs; POSIX stores are restricted explicitly.
            }
            try(FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(encoded);
                while(buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            try {
                if(createOnly) {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE);
                } else {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch(AtomicMoveNotSupportedException e) {
                throw new IOException("Filesystem does not support atomic durable-state replacement", e);
            }
            moved = true;
        } finally {
            if(!moved) Files.deleteIfExists(temporary);
        }
    }

    @FunctionalInterface
    interface IOAction<T> {
        T run() throws IOException;
    }
}
