package com.sparrowwallet.drongo.antiexfil;

import java.nio.file.Files;
import java.nio.file.Path;

public final class AntiExfilExchangeLeaseProbe {
    public static void main(String[] args) throws Exception {
        try(var lease = AntiExfilExchangeLease.acquire(Path.of(args[0]))) {
            Files.writeString(Path.of(args[1]), "owned");
            System.in.read();
            lease.check();
        }
    }
}
