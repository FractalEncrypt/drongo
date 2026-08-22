package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;

final class AntiExfilDurableFiles {
    private static final ConcurrentHashMap<Path, LocalLock> LOCAL_LOCKS = new ConcurrentHashMap<>();
    private static final ReentrantLock JVM_DURABLE_LOCK = new ReentrantLock(true);

    private AntiExfilDurableFiles() {
    }

    static Path canonicalPath(Path target) {
        if(target == null) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                    "Durable anti-exfil state path is required");
        }
        try {
            Path absolute = target.toAbsolutePath().normalize();
            Path parent = absolute.getParent();
            if(parent == null) throw new IOException("Durable state requires a parent directory");
            Files.createDirectories(parent);
            Path realParent = parent.toRealPath();
            Path resolved = realParent.resolve(absolute.getFileName()).normalize();
            return Files.exists(resolved) ? resolved.toRealPath() : resolved;
        } catch(IOException e) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                    "Cannot resolve durable anti-exfil state: " + e.getMessage(), e);
        }
    }

    static <T> T locked(Path target, IOAction<T> action) {
        JVM_DURABLE_LOCK.lock();
        try {
            return lockedInJvm(target, action);
        } finally {
            JVM_DURABLE_LOCK.unlock();
        }
    }

    private static <T> T lockedInJvm(Path target, IOAction<T> action) {
        Path lockPath = null;
        LocalLock local = null;
        try {
            Path canonical = canonicalPath(target);
            lockPath = canonical.getParent().resolve(canonical.getFileName() + ".lock");
            Path localKey = lockPath;
            local = LOCAL_LOCKS.compute(localKey, (ignored, existing) -> {
                LocalLock selected = existing == null ? new LocalLock() : existing;
                selected.references++;
                return selected;
            });
            local.lock.lock();
            try(FileChannel pathChannel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                FileLock ignoredPath = pathChannel.lock()) {
                if(Files.exists(canonical) && !isWindows()) {
                    try(FileChannel stateChannel = FileChannel.open(canonical,
                            StandardOpenOption.READ, StandardOpenOption.WRITE);
                        FileLock ignoredState = stateChannel.lock()) {
                        return action.run();
                    }
                }
                // Windows does not permit atomic replacement while this process holds a FileChannel
                // lock on the target. JVM_DURABLE_LOCK still serializes in-process aliases there;
                // cross-process hard-link aliases remain a documented trusted-filesystem residual.
                return action.run();
            }
        } catch(OverlappingFileLockException e) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                    "Durable anti-exfil state is already locked in this process", e);
        } catch(IOException e) {
            throw new AntiExfilException(AntiExfilException.Code.STATE_INVALID,
                    "Cannot access durable anti-exfil state: " + e.getMessage(), e);
        } finally {
            if(local != null) {
                local.lock.unlock();
                LocalLock released = local;
                LOCAL_LOCKS.compute(lockPath, (ignored, existing) -> {
                    if(existing != released) return existing;
                    return --released.references == 0 ? null : released;
                });
            }
        }
    }

    static byte[] read(Path path, int maximumBytes) throws IOException {
        if(maximumBytes < 32) throw new IOException("State length limit is invalid");
        byte[] encoded;
        try(FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            long size = channel.size();
            if(size < 32 || size > maximumBytes) throw new IOException("State length is outside limits");
            encoded = new byte[Math.toIntExact(size)];
            ByteBuffer buffer = ByteBuffer.wrap(encoded);
            while(buffer.hasRemaining()) {
                if(channel.read(buffer) < 0) throw new IOException("State was truncated while being read");
            }
            if(channel.read(ByteBuffer.allocate(1)) >= 0) {
                throw new IOException("State grew while being read");
            }
        }
        byte[] body = Arrays.copyOf(encoded, encoded.length - 32);
        byte[] checksum = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        if(!Arrays.equals(Sha256Hash.hash(body), checksum)) throw new IOException("State checksum mismatch");
        return body;
    }

    static void write(Path path, byte[] body, boolean createOnly, int maximumBytes) throws IOException {
        write(path, body, createOnly, maximumBytes, AntiExfilDurableFiles::forceParentDirectory);
    }

    static void write(Path path, byte[] body, boolean createOnly, int maximumBytes,
                      DirectoryBarrier directoryBarrier) throws IOException {
        if(body == null || maximumBytes < 32 || body.length > maximumBytes - 32) {
            throw new IOException("State length is outside limits");
        }
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
                if(!createOnly && Files.exists(absolute)) {
                    // Replacement detaches hard-link aliases. Invalidate and force the locked old inode
                    // first so no detached alias retains a valid pre-transition security state.
                    invalidate(absolute);
                }
                if(createOnly) {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE);
                } else {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch(AtomicMoveNotSupportedException e) {
                throw new IOException("Filesystem does not support atomic durable-state replacement", e);
            }
            moved = true;
            try {
                directoryBarrier.force(parent);
            } catch(IOException e) {
                // The new state is visible but did not cross the required durability barrier. Make it
                // unreadable before failing so an exact retry cannot disclose data from that state.
                try {
                    invalidate(absolute);
                } catch(IOException invalidationFailure) {
                    e.addSuppressed(invalidationFailure);
                }
                throw e;
            }
        } finally {
            if(!moved) Files.deleteIfExists(temporary);
        }
    }

    private static void invalidate(Path path) throws IOException {
        try(FileChannel channel = FileChannel.open(path, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            channel.force(true);
        }
    }

    private static void forceParentDirectory(Path parent) throws IOException {
        try(FileChannel channel = FileChannel.open(parent, StandardOpenOption.READ)) {
            channel.force(true);
        } catch(UnsupportedOperationException | IOException e) {
            if(!isWindows()) {
                if(e instanceof IOException io) throw io;
                throw new IOException("Filesystem does not support parent-directory durability", e);
            }
            // Java cannot portably open directory handles on Windows. File content forcing and atomic
            // replacement still apply; crash-time directory-entry persistence is a documented residual.
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("windows");
    }

    @FunctionalInterface
    interface IOAction<T> {
        T run() throws IOException;
    }

    @FunctionalInterface
    interface DirectoryBarrier {
        void force(Path parent) throws IOException;
    }

    private static final class LocalLock {
        private final ReentrantLock lock = new ReentrantLock(true);
        private int references;
    }
}
