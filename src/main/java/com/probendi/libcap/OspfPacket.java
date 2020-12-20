package com.probendi.libcap;

import java.text.ParseException;
import java.util.Arrays;

import org.jetbrains.annotations.Contract;

import static com.probendi.libcap.Validator.validateObject;

/**
 * An OSPFv2 packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class OspfPacket {

    /**
     * An OSPFv2 packet's type.
     */
    public enum Type {
        HELLO(1), DB_DESCRIPTION(2), LS_REQUEST(3), LS_UPDATE(4), LS_ACKNOWLEDGE(5);

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
     * An OSPFv2 packet's authentication type.
     */
    public enum AuType {
        NO_AUTHENTICATION, SIMPLE_PASSWORD, RESERVED;

        private byte type;

        /**
         * Returns the authentication type for the given byte.
         *
         * @param b the byte
         * @return the authentication type for the given byte
         */
        @Contract(pure = true)
        public static AuType parse(final char b) {
            return b == 0 ? NO_AUTHENTICATION : b == 1 ? SIMPLE_PASSWORD : RESERVED;
        }
    }

    /**
     * Parses an OSPF packet from the given bytes.
     *
     * @param bytes the bytes to be parsed
     * @return an OSPF packet
     * @throws IllegalArgumentException if {@code bytes} is not set
     * @throws ParseException           if the bytes cannot be parsed
     */
    public static OspfPacket parse(final byte[] bytes) throws ParseException {
        validateObject("record", bytes);
        final OspfPacket packet = new OspfPacket();
        packet.version = bytes[0];
        packet.type = Type.parse(bytes[1]);
        packet.length = Parser.readChar(bytes[2], bytes[3]);
        packet.routerId = Arrays.copyOfRange(bytes, 4, 8);
        packet.areaId = Arrays.copyOfRange(bytes, 8, 12);
        packet.checksum = Parser.readChar(bytes[12], bytes[13]);
        packet.auType = AuType.parse(Parser.readChar(bytes[14], bytes[15]));
        packet.authentication = Arrays.copyOfRange(bytes, 16, 24);
        packet.payload = Arrays.copyOfRange(bytes, 24, bytes.length);
        return packet;
    }

    private byte version;
    private Type type;
    private char length;
    private byte[] routerId;
    private byte[] areaId;
    private char checksum;
    private AuType auType;
    private byte[] authentication;
    private byte[] payload;

    public byte getVersion() {
        return version;
    }

    public OspfPacket version(final byte version) {
        this.version = version;
        return this;
    }

    public Type getType() {
        return type;
    }

    public OspfPacket type(final Type type) {
        this.type = type;
        return this;
    }

    public char getLength() {
        return length;
    }

    public OspfPacket length(final char length) {
        this.length = length;
        return this;
    }

    public byte[] getRouterId() {
        return routerId;
    }

    public OspfPacket routerId(final byte[] routerId) {
        this.routerId = routerId;
        return this;
    }

    public byte[] getAreaId() {
        return areaId;
    }

    public OspfPacket areaId(final byte[] areaId) {
        this.areaId = areaId;
        return this;
    }

    public char getChecksum() {
        return checksum;
    }

    public OspfPacket checksum(final char checksum) {
        this.checksum = checksum;
        return this;
    }

    public AuType getAuType() {
        return auType;
    }

    public OspfPacket auType(final AuType auType) {
        this.auType = auType;
        return this;
    }

    public byte[] getAuthentication() {
        return authentication;
    }

    public OspfPacket authentication(final byte[] authentication) {
        this.authentication = authentication;
        return this;
    }

    public byte[] getPayload() {
        return payload;
    }

    public OspfPacket payload(final byte[] payload) {
        this.payload = payload;
        return this;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof OspfPacket)) return false;
        final OspfPacket that = (OspfPacket) o;
        return getVersion() == that.getVersion() &&
                getLength() == that.getLength() &&
                getChecksum() == that.getChecksum() &&
                getType() == that.getType() &&
                Arrays.equals(getRouterId(), that.getRouterId()) &&
                Arrays.equals(getAreaId(), that.getAreaId()) &&
                getAuType() == that.getAuType() &&
                Arrays.equals(getAuthentication(), that.getAuthentication()) &&
                Arrays.equals(getPayload(), that.getPayload());
    }
}
