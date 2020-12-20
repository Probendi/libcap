package com.probendi.libcap;

import java.util.Arrays;

import static com.probendi.libcap.Validator.validateObject;

/**
 * An ICMP packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class IcmpPacket {

    /**
     * Parses an ICMP packet from the given bytes.
     *
     * @param bytes the bytes to be parsed
     * @return an ICMP packet
     * @throws IllegalArgumentException if {@code bytes} is not not set
     */
    public static IcmpPacket parse(final byte[] bytes) {
        validateObject("bytes", bytes);
        final IcmpPacket packet = new IcmpPacket();
        packet.type = bytes[0];
        packet.code = bytes[1];
        packet.checksum = Parser.readChar(bytes[2], bytes[3]);
        packet.restOfHeader = Parser.readInt(bytes[4], bytes[5], bytes[6], bytes[7]);
        packet.data = Arrays.copyOfRange(bytes, 8, bytes.length);
        return packet;
    }

    private byte type;
    private byte code;
    private char checksum;
    private int restOfHeader;
    private byte[] data;

    public byte getType() {
        return type;
    }

    public IcmpPacket type(final byte type) {
        this.type = type;
        return this;
    }

    public byte getCode() {
        return code;
    }

    public IcmpPacket code(final byte code) {
        this.code = code;
        return this;
    }

    public char getChecksum() {
        return checksum;
    }

    public IcmpPacket checksum(final char checksum) {
        this.checksum = checksum;
        return this;
    }

    public int getRestOfHeader() {
        return restOfHeader;
    }

    public IcmpPacket restOfHeader(final int restOfHeader) {
        this.restOfHeader = restOfHeader;
        return this;
    }

    public byte[] getData() {
        return data;
    }

    public IcmpPacket data(final byte[] data) {
        this.data = data;
        return this;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof IcmpPacket)) return false;
        final IcmpPacket that = (IcmpPacket) o;
        return getType() == that.getType() &&
                getCode() == that.getCode() &&
                getChecksum() == that.getChecksum() &&
                getRestOfHeader() == that.getRestOfHeader() &&
                Arrays.equals(getData(), that.getData());
    }
}
