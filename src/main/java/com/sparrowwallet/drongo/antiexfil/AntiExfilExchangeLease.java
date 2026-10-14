package com.sparrowwallet.drongo.antiexfil;

import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/** Lifetime ownership. Never open a second lease channel after a failed JVM claim:
 * closing it could release process-scoped POSIX locks held by the first owner. */
final class AntiExfilExchangeLease implements AutoCloseable {
    private static final ConcurrentHashMap<Path, Object> OWNERS = new ConcurrentHashMap<>();
    private final Path path;
    private final Object owner;
    private FileChannel channel;
    private FileLock lock;
    private Object identity;
    private boolean closed;

    private AntiExfilExchangeLease(Path path, Object owner) { this.path = path; this.owner = owner; }

    static AntiExfilExchangeLease acquire(Path directory) {
        final Path path;
        try {
            Files.createDirectories(directory);
            path = directory.toRealPath().resolve("exchange.lease");
        } catch(IOException e) { throw storage(e); }
        Object token = new Object();
        if(OWNERS.putIfAbsent(path, token) != null) throw busy();
        AntiExfilExchangeLease lease = new AntiExfilExchangeLease(path, token);
        try {
            lease.channel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
            try { lease.lock = lease.channel.tryLock(); }
            catch(OverlappingFileLockException e) { throw busy(); }
            if(lease.lock == null) throw busy();
            lease.identity = HandleIdentity.of(lease.channel);
            lease.check();
            return lease;
        } catch(Exception e) {
            lease.close(); // E3: removes only this token, on every failed acquire path.
            if(e instanceof AntiExfilException ae) throw ae;
            throw storage(e);
        }
    }

    synchronized void check() {
        try {
            if(closed || OWNERS.get(path) != owner || channel == null || !channel.isOpen() || lock == null || !lock.isValid())
                throw new IOException("Exchange ownership is no longer valid");
            if(!identity.equals(HandleIdentity.of(channel)) || !identity.equals(HandleIdentity.at(path)))
                throw new IOException("The live lease file was removed or replaced");
        } catch(Exception e) {
            close();
            throw storage(e);
        }
    }

    @Override public synchronized void close() {
        if(closed) return;
        closed = true;
        try { if(lock != null) lock.release(); } catch(IOException ignored) { }
        finally {
            try { if(channel != null) channel.close(); } catch(IOException ignored) { }
            finally { OWNERS.remove(path, owner); }
        }
    }

    private static AntiExfilException busy() {
        return new AntiExfilException(AntiExfilException.Code.ACCOUNT_EXCHANGE_BUSY,
                "Another Protected QR exchange owns this account. Finish or close that exchange before starting another.");
    }
    private static AntiExfilException storage(Exception cause) {
        return new AntiExfilException(AntiExfilException.Code.HISTORY_STORAGE_ERROR,
                "Cannot validate Protected QR ownership. Preserve the history files and investigate storage/runtime configuration.", cause);
    }

    /** Pinned JDK25 adapter. No path-snapshot fallback: Windows BasicFileAttributes
     * has no fileKey. Explicit module opens are required and reviewed with the build. */
    private static final class HandleIdentity {
        private static final boolean WINDOWS = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows");
        static Object of(FileChannel channel) throws Exception {
            Field field = Class.forName("sun.nio.ch.FileChannelImpl").getDeclaredField("fd");
            field.setAccessible(true);
            FileDescriptor descriptor = (FileDescriptor)field.get(channel);
            Field nativeField = FileDescriptor.class.getDeclaredField(WINDOWS ? "handle" : "fd");
            nativeField.setAccessible(true);
            if(WINDOWS) return windows(nativeField.getLong(descriptor));
            Class<?> attrs = Class.forName("sun.nio.fs.UnixFileAttributes");
            Object value = call(attrs, "get", new Class<?>[]{int.class}, null, nativeField.getInt(descriptor));
            return call(attrs, "fileKey", new Class<?>[0], value);
        }
        static Object at(Path path) throws Exception {
            if(!WINDOWS) {
                Object key = Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class).fileKey();
                if(key == null) throw new IOException("Native file identity is unavailable");
                return key;
            }
            long handle = (long)call(path.getClass(), "openForReadAttributeAccess", new Class<?>[]{boolean.class}, path, true);
            try { return windows(handle); }
            finally { call(Class.forName("sun.nio.fs.WindowsNativeDispatcher"), "CloseHandle", new Class<?>[]{long.class}, null, handle); }
        }
        private static Object windows(long handle) throws Exception {
            Class<?> attrs = Class.forName("sun.nio.fs.WindowsFileAttributes");
            Object value = call(attrs, "readAttributes", new Class<?>[]{long.class}, null, handle);
            return new WindowsIdentity((int)call(attrs, "volSerialNumber", new Class<?>[0], value),
                    (int)call(attrs, "fileIndexHigh", new Class<?>[0], value),
                    (int)call(attrs, "fileIndexLow", new Class<?>[0], value));
        }
        private static Object call(Class<?> type, String name, Class<?>[] args, Object target, Object... values) throws Exception {
            Method method = type.getDeclaredMethod(name, args);
            method.setAccessible(true);
            return method.invoke(target, values);
        }
        private record WindowsIdentity(int volume, int high, int low) { }
    }
}
