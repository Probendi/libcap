package com.probendi.libcap;

import java.util.Arrays;

import static com.probendi.libcap.PacketType.IPv4;
import static com.probendi.libcap.PacketType.IPv6;
import static com.probendi.libcap.PacketType.PPPoE_DISC;
import static com.probendi.libcap.PacketType.PPPoE_SESS;
import static com.probendi.libcap.Parser.readChar;
import static com.probendi.libcap.Validator.validateObject;

/**
 * A Dot1Q packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class Dot1QPacket {

    /**
     * Parses a Dot1Q packet from the given record.
     *
     * @param record the record to be parsed
     * @return a Dot1Q packet
     * @throws IllegalArgumentException if {@code record} is not set
     */
    public static Dot1QPacket parse(final Record record) {
        validateObject("record", record);
        final Dot1QPacket packet = new Dot1QPacket();
        final byte[] bytes = record.getBytes();
        final int i = 0xe;
        packet.priority = (byte) ((bytes[0xe] & 0xe0) >> 5);
        packet.dei = (bytes[0xe] & 0x10) == 0x10;
        packet.id = (char) (readChar(bytes[0xe], bytes[0xf]) & 0xfff);
        packet.type = PacketType.parse(readChar(bytes[0x10], bytes[0x11]));
        packet.payload = Arrays.copyOfRange(bytes, 0x12, bytes.length);
        return packet;
    }

    private byte priority;
    private boolean dei;
    private char id;
    private PacketType type;
    private byte[] payload;

    public byte getPriority() {
        return priority;
    }

    public Dot1QPacket priority(final byte priority) {
        this.priority = priority;
        return this;
    }

    public boolean isDei() {
        return dei;
    }

    public Dot1QPacket dei(final boolean dei) {
        this.dei = dei;
        return this;
    }

    public char getId() {
        return id;
    }

    public Dot1QPacket id(final char id) {
        this.id = id;
        return this;
    }

    public PacketType getType() {
        return type;
    }

    public Dot1QPacket type(final PacketType type) {
        this.type = type;
        return this;
    }

    public byte[] getPayload() {
        return payload;
    }

    public Dot1QPacket payload(final byte[] payload) {
        this.payload = payload;
        return this;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof Dot1QPacket)) return false;
        final Dot1QPacket that = (Dot1QPacket) o;
        return getPriority() == that.getPriority() &&
                isDei() == that.isDei() &&
                getId() == that.getId() &&
                getType() == that.getType() &&
                Arrays.equals(getPayload(), that.getPayload());
    }

    /**
     * Returns {@code true} if this packet contains an IPv4 packet.
     *
     * @return {@code true} if this packet contains an IPv4 packet
     */
    public boolean hasIpv4() {
        return type == IPv4;
    }

    /**
     * Returns {@code true} if this packet contains an IPv6 packet.
     *
     * @return {@code true} if this packet contains an IPv6 packet
     */
    public boolean hasIpv6() {
        return type == IPv6;
    }

    /**
     * Returns {@code true} if this packet contains a PPPoE Discovery packet.
     *
     * @return {@code true} if this packet contains a PPPoE Discovery packet
     */
    public boolean hasPppoEDiscoveryPacket() {
        return type == PPPoE_DISC;
    }

    /**
     * Returns {@code true} if this packet contains a PPPoE Session packet.
     *
     * @return {@code true} if this packet contains a PPPoE Session packet
     */
    public boolean hasPppoESessionPacket() {
        return type == PPPoE_SESS;
    }
}
