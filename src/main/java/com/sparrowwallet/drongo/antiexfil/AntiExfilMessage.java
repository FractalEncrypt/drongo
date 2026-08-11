package com.sparrowwallet.drongo.antiexfil;

import java.util.Arrays;
import java.util.List;

public final class AntiExfilMessage {
    private final AntiExfilNetwork network;
    private final AntiExfilStage stage;
    private final byte[] sessionId;
    private final byte[] psbtDigest;
    private final List<AntiExfilSlot> slots;

    public AntiExfilMessage(AntiExfilNetwork network, AntiExfilStage stage, byte[] sessionId,
                            byte[] psbtDigest, List<AntiExfilSlot> slots) {
        this.network = network;
        this.stage = stage;
        this.sessionId = sessionId == null ? null : sessionId.clone();
        this.psbtDigest = psbtDigest == null ? null : psbtDigest.clone();
        this.slots = slots == null ? null : List.copyOf(slots);
    }

    public AntiExfilNetwork getNetwork() { return network; }
    public AntiExfilStage getStage() { return stage; }
    public byte[] getSessionId() { return sessionId == null ? null : sessionId.clone(); }
    public byte[] getPsbtDigest() { return psbtDigest == null ? null : psbtDigest.clone(); }
    public List<AntiExfilSlot> getSlots() { return slots; }

    @Override
    public boolean equals(Object object) {
        if(this == object) return true;
        if(!(object instanceof AntiExfilMessage other)) return false;
        return network == other.network && stage == other.stage
                && Arrays.equals(sessionId, other.sessionId)
                && Arrays.equals(psbtDigest, other.psbtDigest)
                && slots.equals(other.slots);
    }

    @Override
    public int hashCode() {
        int result = network.hashCode();
        result = 31 * result + stage.hashCode();
        result = 31 * result + Arrays.hashCode(sessionId);
        result = 31 * result + Arrays.hashCode(psbtDigest);
        return 31 * result + slots.hashCode();
    }
}
