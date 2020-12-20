package com.probendi.libcap;

import java.text.ParseException;
import java.util.Arrays;

import org.jetbrains.annotations.Contract;

import static com.probendi.libcap.Parser.readChar;
import static com.probendi.libcap.Validator.validateObject;

/**
 * An LCP packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class LcpPacket {

    /**
     * An LCP packet's code.
     */
    public enum Code {

        CONFIGURE_REQUEST(1),
        CONFIGURE_ACK(2),
        CONFIGURE_NACK(3),
        CONFIGURE_REJECT(4),
        TERMINATE_REQUEST(5),
        TERMINATE_ACK(6),
        CODE_REJECT(7),
        PROTOCOL_REJECT(8),
        ECHO_REQUEST(9),
        ECHO_REPLY(10),
        DISCARD_REQUEST(11);

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
     * Parses an LCP packet from the given bytes.
     *
     * @param bytes the bytes to be parsed
     * @return a PPPoE Session packet
     * @throws IllegalArgumentException if {@code bytes} is not set
     * @throws ParseException           if the bytes cannot be parsed
     */
    public static LcpPacket parse(final byte[] bytes) throws ParseException {
        validateObject("bytes", bytes);
        final LcpPacket packet = new LcpPacket();
        packet.code = Code.parse(bytes[0]);
        packet.identifier = bytes[1];
        packet.length = readChar(bytes[2], bytes[3]);
        packet.data = Arrays.copyOfRange(bytes, 4, packet.length);
        return packet;
    }

    private Code code;
    private byte identifier;
    private char length;
    private byte[] data;

    public Code getCode() {
        return code;
    }

    public LcpPacket code(final Code code) {
        this.code = code;
        return this;
    }

    public byte getIdentifier() {
        return identifier;
    }

    public LcpPacket identifier(final byte identifier) {
        this.identifier = identifier;
        return this;
    }

    public char getLength() {
        return length;
    }

    public LcpPacket length(final char length) {
        this.length = length;
        return this;
    }

    public byte[] getData() {
        return data;
    }

    public LcpPacket data(final byte[] data) {
        this.data = data;
        return this;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof LcpPacket)) return false;
        final LcpPacket lcpPacket = (LcpPacket) o;
        return getIdentifier() == lcpPacket.getIdentifier() &&
                getLength() == lcpPacket.getLength() &&
                getCode() == lcpPacket.getCode() &&
                Arrays.equals(getData(), lcpPacket.getData());
    }
}
