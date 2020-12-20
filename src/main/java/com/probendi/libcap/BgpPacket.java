package com.probendi.libcap;

import java.text.ParseException;
import java.util.Arrays;

import org.jetbrains.annotations.Contract;

/**
 * A BGPv4 packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class BgpPacket {

    /**
     * A PPPoE packet's type.
     */
    public enum Type {
        OPEN(1), UPDATE(2), NOTIFICATION(3), KEEP_ALIVE(4), ROUTE_REFRESH(5);

        private final byte type;

        Type(final int type) {
            this.type = (byte) type;
        }

        @Contract(pure = true)
        public byte getType() {
            return type;
        }

        /**
         * Returns the type for the given byte.
         *
         * @param b the byte
         * @return the type for the given byte
         * @throws ParseException if the byte cannot be parsed
         */
        public static Type parse(final byte b) throws ParseException {
            for (final Type type : Type.values()) {
                if (type.getType() == b)
                    return type;
            }
            throw new ParseException("invalid type", b);
        }
    }

    /**
     * Parses a BGP packet from the given bytes.
     *
     * @param bytes the bytes to be parsed
     * @return a BGPv4 packet
     * @throws ParseException           if the bytes cannot be parsed
     * @throws IllegalArgumentException if {@code bytes} is not set
     */
    public static BgpPacket parse(final byte[] bytes) throws ParseException {
        Validator.validateObject("payload", bytes);
        final BgpPacket packet = new BgpPacket();
        packet.marker = Arrays.copyOfRange(bytes, 0, 16);
        packet.length = Parser.readChar(bytes[16], bytes[17]);
        packet.type = Type.parse(bytes[18]);
        packet.payload = Arrays.copyOfRange(bytes, 19, bytes.length);
        return packet;
    }

    private byte[] marker;
    private char length;
    private Type type;
    private byte[] payload;

    public byte[] getMarker() {
        return marker;
    }

    public BgpPacket marker(final byte[] marker) {
        this.marker = marker;
        return this;
    }

    public char getLength() {
        return length;
    }

    public BgpPacket length(final char length) {
        this.length = length;
        return this;
    }

    public Type getType() {
        return type;
    }

    public BgpPacket type(final Type type) {
        this.type = type;
        return this;
    }

    public byte[] getPayload() {
        return payload;
    }

    public BgpPacket payload(final byte[] payload) {
        this.payload = payload;
        return this;
    }

    public int getPayloadLength() {
        return payload.length;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof BgpPacket)) return false;
        final BgpPacket packet = (BgpPacket) o;
        return getLength() == packet.getLength() &&
                Arrays.equals(getMarker(), packet.getMarker()) &&
                getType() == packet.getType() &&
                Arrays.equals(getPayload(), packet.getPayload());
    }
}
