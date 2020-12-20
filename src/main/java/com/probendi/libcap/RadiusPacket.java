package com.probendi.libcap;

import java.text.ParseException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import org.jetbrains.annotations.Contract;

import static com.probendi.libcap.Parser.readChar;
import static com.probendi.libcap.Validator.validateObject;

/**
 * A RADIUS packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class RadiusPacket {

    /**
     * A RADIUS packet's code.
     */
    public enum Code {

        ACCESS_REQUEST(1),
        ACCESS_ACCEPT(2),
        ACCESS_REJECT(3),
        ACCOUNTING_REQUEST(4),
        ACCOUNTING_RESPONSE(5),
        ACCESS_CHALLENGE(11),
        DISCONNECT_REQUEST(40),
        DISCONNECT_ACK(41),
        DISCONNECT_NACK(42),
        COA_REQUEST(43),
        COA_ACK(44),
        COA_NACK(45);

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
     * Parses a RADIUS packet from the given bytes.
     *
     * @param bytes the bytes to be parsed
     * @return a RADIUS packet
     * @throws IllegalArgumentException if {@code bytes} is not set
     * @throws ParseException           if the bytes cannot be parsed
     */
    public static RadiusPacket parse(final byte[] bytes) throws ParseException {
        validateObject("bytes", bytes);
        final RadiusPacket packet = new RadiusPacket();
        packet.code = Code.parse(bytes[0]);
        packet.identifier = bytes[1];
        packet.length = readChar(bytes[2], bytes[3]);
        packet.authenticator = Arrays.copyOfRange(bytes, 4, 20);
        int i = 20;
        while (i < packet.length) {
            packet.attributeValuePairs.add(AttributeValuePair.parse(Arrays.copyOfRange(bytes, i, i + bytes[i + 1] + 2)));
            i += bytes[i + 1];
        }
        return packet;
    }

    private Code code;
    private byte identifier;
    private char length;
    private byte[] authenticator;
    private List<AttributeValuePair> attributeValuePairs = new LinkedList<>();

    public Code getCode() {
        return code;
    }

    public RadiusPacket code(final Code code) {
        this.code = code;
        return this;
    }

    public byte getIdentifier() {
        return identifier;
    }

    public RadiusPacket identifier(final byte identifier) {
        this.identifier = identifier;
        return this;
    }

    public char getLength() {
        return length;
    }

    public RadiusPacket length(final char length) {
        this.length = length;
        return this;
    }

    public byte[] getAuthenticator() {
        return authenticator;
    }

    public RadiusPacket authenticator(final byte[] authenticator) {
        this.authenticator = authenticator;
        return this;
    }

    public List<AttributeValuePair> getAttributeValuePairs() {
        return attributeValuePairs;
    }

    public RadiusPacket attributeValuePairs(final List<AttributeValuePair> attributeValuePairs) {
        this.attributeValuePairs = attributeValuePairs;
        return this;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof RadiusPacket)) return false;
        final RadiusPacket that = (RadiusPacket) o;
        return getIdentifier() == that.getIdentifier() &&
                getLength() == that.getLength() &&
                getCode() == that.getCode() &&
                Arrays.equals(getAuthenticator(), that.getAuthenticator()) &&
                Objects.equals(getAttributeValuePairs(), that.getAttributeValuePairs());
    }

    /**
     * An attribute-value pair (AVP)
     */
    public static class AttributeValuePair {

        /**
         * Parses an AVP from the given bytes.
         *
         * @param bytes the bytes to be parsed
         * @return an AVP
         * @throws IllegalArgumentException if {@code bytes} is not set
         */
        public static AttributeValuePair parse(final byte[] bytes) {
            validateObject("bytes", bytes);
            final AttributeValuePair packet = new AttributeValuePair();
            packet.type = bytes[0];
            packet.length = bytes[1];
            if (packet.type == 26) {
                packet.vendorSpecificAttributes = new LinkedList<>();
                int i = 6;
                while (i < packet.length) {
                    packet.vendorSpecificAttributes.add(VendorSpecificAttribute.parse(Arrays.copyOfRange(bytes, i, i + bytes[i + 1] + 2)));
                    i += bytes[i + 1];
                }
            } else {
                packet.value = Arrays.copyOfRange(bytes, 2, packet.length);
            }
            return packet;
        }

        private byte type;
        private byte length;
        private byte[] value;
        private List<VendorSpecificAttribute> vendorSpecificAttributes;

        public byte getType() {
            return type;
        }

        public AttributeValuePair type(final byte type) {
            this.type = type;
            return this;
        }

        public byte getLength() {
            return length;
        }

        public AttributeValuePair length(final byte length) {
            this.length = length;
            return this;
        }

        public byte[] getValue() {
            return value;
        }

        public AttributeValuePair value(final byte[] value) {
            this.value = value;
            return this;
        }

        public List<VendorSpecificAttribute> getVendorSpecificAttributes() {
            return vendorSpecificAttributes;
        }

        public AttributeValuePair vendorSpecificAttributes(final List<VendorSpecificAttribute> vendorSpecificAttributes) {
            this.vendorSpecificAttributes = vendorSpecificAttributes;
            return this;
        }

        @Contract(value = "null -> false", pure = true)
        @Override
        public boolean equals(final Object o) {
            if (this == o) return true;
            if (!(o instanceof AttributeValuePair)) return false;
            final AttributeValuePair that = (AttributeValuePair) o;
            return getType() == that.getType() &&
                    getLength() == that.getLength() &&
                    Arrays.equals(getValue(), that.getValue()) &&
                    Objects.equals(getVendorSpecificAttributes(), that.getVendorSpecificAttributes());
        }
    }

    /**
     * A Vendor Specific Attribute(VSA)
     */
    public static class VendorSpecificAttribute {

        /**
         * Parses a VSA from the given bytes.
         *
         * @param bytes the bytes to be parsed
         * @return a VSA
         * @throws IllegalArgumentException if {@code bytes} is not set
         */
        public static VendorSpecificAttribute parse(final byte[] bytes) {
            validateObject("bytes", bytes);
            final VendorSpecificAttribute packet = new VendorSpecificAttribute();
            packet.type = bytes[0];
            packet.length = bytes[1];
            packet.value = Arrays.copyOfRange(bytes, 2, packet.length);
            return packet;
        }

        private byte type;
        private byte length;
        private byte[] value;

        public byte getType() {
            return type;
        }

        public VendorSpecificAttribute type(final byte type) {
            this.type = type;
            return this;
        }

        public byte getLength() {
            return length;
        }

        public VendorSpecificAttribute length(final byte length) {
            this.length = length;
            return this;
        }

        public byte[] getValue() {
            return value;
        }

        public VendorSpecificAttribute value(final byte[] value) {
            this.value = value;
            return this;
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) return true;
            if (!(o instanceof VendorSpecificAttribute)) return false;
            final VendorSpecificAttribute that = (VendorSpecificAttribute) o;
            return getType() == that.getType() &&
                    getLength() == that.getLength() &&
                    Arrays.equals(getValue(), that.getValue());
        }
    }
}
