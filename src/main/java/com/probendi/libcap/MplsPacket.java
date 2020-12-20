package com.probendi.libcap;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * An MPLS packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class MplsPacket {

    /**
     * An MPLS packet's header.
     */
    public static class Header {
        private char label;
        private byte exp;
        private boolean bottom;
        private char ttl;

        public char getLabel() {
            return label;
        }

        public Header label(final char label) {
            this.label = label;
            return this;
        }

        public byte getExp() {
            return exp;
        }

        public Header exp(final byte exp) {
            this.exp = exp;
            return this;
        }

        public boolean isBottom() {
            return bottom;
        }

        public Header bottom(final boolean bottom) {
            this.bottom = bottom;
            return this;
        }

        public char getTtl() {
            return ttl;
        }

        public Header ttl(final char ttl) {
            this.ttl = ttl;
            return this;
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) return true;
            if (!(o instanceof Header)) return false;
            final Header header = (Header) o;
            return getLabel() == header.getLabel() &&
                    getExp() == header.getExp() &&
                    isBottom() == header.isBottom() &&
                    getTtl() == header.getTtl();
        }
    }

    /**
     * Parses an MPLS packet from the given record.
     *
     * @param record the record to be parsed
     * @return an MPLS packet
     * @throws IllegalArgumentException if {@code record} is not not set
     */
    public static MplsPacket parse(final Record record) {
        Validator.validateObject("bytes", record);
        final MplsPacket packet = new MplsPacket();
        packet.headers = new LinkedList<>();
        final byte[] bytes = record.getBytes();
        int i = 0xe;
        while (true) {
            final byte b0 = bytes[i++];
            final byte b1 = bytes[i++];
            final byte b2 = bytes[i++];
            final byte b3 = bytes[i++];

            final Header header = new Header();
            header.label = (char) (Parser.readInt((byte) 0, b0, b1, (byte) (b2 & 0xf0)) >> 4);
            header.exp = (byte) ((b2 & 0b1110) >> 1);
            header.bottom = (b2 & 1) == 1;
            header.ttl = Parser.readChar((byte) 0, b3);
            packet.headers.add(header);
            if (header.bottom) {
                break;
            }
        }
        packet.payload = Arrays.copyOfRange(bytes, i, bytes.length);
        return packet;

    }

    private List<Header> headers;
    private byte[] payload;

    public List<Header> getHeaders() {
        return headers;
    }

    public MplsPacket headers(final List<Header> headers) {
        this.headers = headers;
        return this;
    }

    public byte[] getPayload() {
        return payload;
    }

    public MplsPacket payload(final byte[] payload) {
        this.payload = payload;
        return this;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof MplsPacket)) return false;
        final MplsPacket that = (MplsPacket) o;
        return Objects.equals(getHeaders(), that.getHeaders()) &&
                Arrays.equals(getPayload(), that.getPayload());
    }

    /**
     * Returns {@code true} if this packet contains an IPv4 packet.
     *
     * @return {@code true} if this packet contains an IPv4 packet
     */
    public boolean hasIpv4Packet() {
        return (payload[0] & 0xf0) == (byte) 0x40;
    }

    /**
     * Returns {@code true} if this packet contains an IPv6 packet.
     *
     * @return {@code true} if this packet contains an IPv6 packet
     */
    public boolean hasIpv6Packet() {
        return (payload[0] & 0xf0) == (byte) 0x60;
    }
}
