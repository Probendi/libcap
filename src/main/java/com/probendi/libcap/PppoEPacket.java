package com.probendi.libcap;

import java.text.ParseException;
import java.util.Arrays;

import org.jetbrains.annotations.Contract;

import static com.probendi.libcap.Parser.readChar;
import static com.probendi.libcap.Validator.validateObject;

/**
 * A PPPoE packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class PppoEPacket {

    /**
     * A PPPoE packet's code.
     */
    public enum Code {
        PADI(9), PADO(7), PADR(0x19), PADS(0x65), PADT(0xa7), SESSION_STAGE(0);

        private final byte code;

        Code(final int code) {
            this.code = (byte) code;
        }

        @Contract(pure = true)
        public byte getCode() {
            return code;
        }

        /**
         * Returns the code for the given byte.
         *
         * @param b the byte
         * @return the code for the given byte
         * @throws ParseException if the byte cannot be parsed
         */
        public static Code parse(final byte b) throws ParseException {
            for (final Code type : Code.values()) {
                if (type.getCode() == b)
                    return type;
            }
            throw new ParseException("invalid code", b);
        }
    }

    /**
     * A point-to-point protocol.
     */
    public enum PointToPointProtocol {
        IPV4(0x21),
        IPV6(0x57),
        IPCP(0x8021),
        IPV6CP(0x8057),
        LCP(0xc021),
        PAP(0xc023),
        LQR(0xc025),
        CHAP(0xc223),
        UNSUPPORTED(0xffff);

        private char protocol;

        private final char type;

        PointToPointProtocol(final int type) {
            this.type = (char) type;
        }

        @Contract(pure = true)
        public char getType() {
            return type;
        }

        /**
         * Returns the protocol type for the given bytes.
         *
         * @param b0 the most significant byte
         * @param b1 the least significant byte
         * @return the protocol type for the given bytes
         * @throws ParseException if the bytes cannot be parsed
         */
        public static PointToPointProtocol parse(final byte b0, final byte b1) throws ParseException {
            return parse(readChar(b0, b1));
        }

        /**
         * Returns the protocol type for the given char.
         *
         * @param c the char
         * @return the protocol type for the given char
         * @throws ParseException if the char cannot be parsed
         */
        public static PointToPointProtocol parse(final char c) throws ParseException {
            for (final PointToPointProtocol type : PointToPointProtocol.values()) {
                if (type.getType() == c)
                    return type;
            }
            throw new ParseException("invalid protocol", c);
        }
    }

    /**
     * Parses a PPPoE Session packet from the given bytes.
     *
     * @param bytes the bytes to be parsed
     * @return a PPPoE Session packet
     * @throws IllegalArgumentException if {@code bytes} is not set
     * @throws ParseException           if the bytes cannot be parsed
     */
    public static PppoEPacket parse(final byte[] bytes) throws ParseException {
        validateObject("bytes", bytes);
        final PppoEPacket packet = new PppoEPacket();
        packet.version = (byte) (bytes[0] >> 4);
        packet.type = (byte) ((bytes[0] & (byte) 0xf));
        packet.code = Code.parse(bytes[1]);
        packet.sessionId = readChar(bytes[2], bytes[3]);
        packet.length = readChar(bytes[4], bytes[5]);
        if (packet.code == Code.SESSION_STAGE) {
            packet.pointToPointProtocol = PointToPointProtocol.parse(bytes[6], bytes[7]);
            packet.payload = Arrays.copyOfRange(bytes, 8, bytes.length);
        } else {
            packet.payload = Arrays.copyOfRange(bytes, 6, bytes.length);
        }
        return packet;
    }

    private byte version;
    private byte type;
    private Code code;
    private char sessionId;
    private char length;
    private PointToPointProtocol pointToPointProtocol;
    private byte[] payload;

    public byte getVersion() {
        return version;
    }

    public PppoEPacket version(final byte version) {
        this.version = version;
        return this;
    }

    public byte getType() {
        return type;
    }

    public PppoEPacket type(final byte type) {
        this.type = type;
        return this;
    }

    public Code getCode() {
        return code;
    }

    public PppoEPacket code(final Code code) {
        this.code = code;
        return this;
    }

    public char getSessionId() {
        return sessionId;
    }

    public PppoEPacket sessionId(final char sessionId) {
        this.sessionId = sessionId;
        return this;
    }

    public char getLength() {
        return length;
    }

    public PppoEPacket length(final char length) {
        this.length = length;
        return this;
    }

    public PointToPointProtocol getPointToPointProtocol() {
        return pointToPointProtocol;
    }

    public PppoEPacket pointToPointProtocol(final PointToPointProtocol pointToPointProtocol) {
        this.pointToPointProtocol = pointToPointProtocol;
        return this;
    }

    public byte[] getPayload() {
        return payload;
    }

    public PppoEPacket payload(final byte[] payload) {
        this.payload = payload;
        return this;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof PppoEPacket)) return false;
        final PppoEPacket that = (PppoEPacket) o;
        return getVersion() == that.getVersion() &&
                getType() == that.getType() &&
                getSessionId() == that.getSessionId() &&
                getLength() == that.getLength() &&
                getCode() == that.getCode() &&
                getPointToPointProtocol() == that.getPointToPointProtocol() &&
                Arrays.equals(getPayload(), that.getPayload());
    }

    /**
     * Returns {@code true} if this protocol encapsulates an IPv4 packet.
     *
     * @return {@code true} if this protocol encapsulates an IPv4 packet
     */
    public boolean hasIpv4() {
        return pointToPointProtocol == PointToPointProtocol.IPV4;
    }

    /**
     * Returns {@code true} if this protocol encapsulates an IPv6 packet.
     *
     * @return {@code true} if this protocol encapsulates an IPv6 packet
     */
    public boolean hasIpv6() {
        return pointToPointProtocol == PointToPointProtocol.IPV6;
    }
}
