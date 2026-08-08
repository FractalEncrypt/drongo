package com.sparrowwallet.drongo.antiexfil;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

public final class AntiExfilCrypto {
    private static final String DATA_TAG = "s2c/ecdsa/data";
    private static final String POINT_TAG = "s2c/ecdsa/point";

    private AntiExfilCrypto() {
    }

    public static byte[] hostCommit(byte[] hostRandomness) {
        if(hostRandomness == null || hostRandomness.length != 32) {
            throw new AntiExfilException(AntiExfilException.Code.INVALID_MESSAGE, "Host randomness must be exactly 32 bytes");
        }
        return Utils.taggedHash(DATA_TAG, hostRandomness);
    }

    public static boolean verify(byte[] publicKey, byte[] messageHash, byte[] hostRandomness,
                                 byte[] opening, byte[] compactSignature) {
        if(length(publicKey) != 33 || length(messageHash) != 32 || length(hostRandomness) != 32
                || length(opening) != 33 || length(compactSignature) != 64) return false;
        try {
            ECPoint openingPoint = ECKey.CURVE.getCurve().decodePoint(opening).normalize();
            if(openingPoint.isInfinity()) return false;
            byte[] tweakHash = Utils.taggedHash(POINT_TAG, Utils.concat(openingPoint.getEncoded(true), hostRandomness));
            BigInteger tweak = new BigInteger(1, tweakHash);
            if(tweak.compareTo(ECKey.CURVE.getN()) >= 0) return false;
            ECPoint committedPoint = openingPoint.add(ECKey.CURVE.getG().multiply(tweak)).normalize();
            if(committedPoint.isInfinity()) return false;
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(compactSignature, 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(compactSignature, 32, 64));
            if(r.signum() <= 0 || r.compareTo(ECKey.CURVE.getN()) >= 0 || s.signum() <= 0 || s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) return false;
            if(!committedPoint.getAffineXCoord().toBigInteger().mod(ECKey.CURVE.getN()).equals(r)) return false;
            TransactionSignature signature = new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
            return ECKey.fromPublicOnly(publicKey).verify(messageHash, signature);
        } catch(Exception e) {
            return false;
        }
    }

    private static int length(byte[] value) {
        return value == null ? -1 : value.length;
    }
}
