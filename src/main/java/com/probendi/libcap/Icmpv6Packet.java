package com.probendi.libcap;

import java.util.Arrays;

/**
 * An ICMPv6 packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class Icmpv6Packet {

    /**
     * Parses an ICMPv6 packet from the given bytes.
     *
     * @param bytes the bytes to be parsed
     * @return an ICMPv6 packet
     * @throws IllegalArgumentException if {@code bytes} is not not set
     */
    public static Icmpv6Packet parse(final byte[] bytes) {
        Validator.validateObject("bytes", bytes);
        final Icmpv6Packet packet = new Icmpv6Packet();
        packet.type = bytes[0];
        packet.code = bytes[1];
        packet.checksum = Parser.readChar(bytes[2], bytes[3]);
        packet.data = Arrays.copyOfRange(bytes, 8, bytes.length);
        return packet;
    }

    private byte type;
    private byte code;
    private char checksum;
    private byte[] data;

    public byte getType() {
        return type;
    }

    public Icmpv6Packet type(final byte type) {
        this.type = type;
        return this;
    }

    public byte getCode() {
        return code;
    }

    public Icmpv6Packet code(final byte code) {
        this.code = code;
        return this;
    }

    public char getChecksum() {
        return checksum;
    }

    public Icmpv6Packet checksum(final char checksum) {
        this.checksum = checksum;
        return this;
    }

    public byte[] getData() {
        return data;
    }

    public Icmpv6Packet data(final byte[] data) {
        this.data = data;
        return this;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof Icmpv6Packet)) return false;
        final Icmpv6Packet that = (Icmpv6Packet) o;
        return getType() == that.getType() &&
                getCode() == that.getCode() &&
                getChecksum() == that.getChecksum() &&
                Arrays.equals(getData(), that.getData());
    }
}
