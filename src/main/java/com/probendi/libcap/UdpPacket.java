package com.probendi.libcap;

import java.util.Arrays;

import static com.probendi.libcap.Validator.validateObject;

/**
 * A UDP packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class UdpPacket {

    /**
     * Parses a UDP packet from the given bytes.
     *
     * @param bytes the bytes to be parsed
     * @return a TCP packet
     * @throws IllegalArgumentException if {@code bytes} is not not set
     */
    public static UdpPacket parse(final byte[] bytes) {
        validateObject("bytes", bytes);
        final UdpPacket packet = new UdpPacket();
        packet.sourcePort = Parser.readChar(bytes[0], bytes[1]);
        packet.destinationPort = Parser.readChar(bytes[2], bytes[3]);
        packet.length = Parser.readChar(bytes[4], bytes[5]);
        packet.checksum = Parser.readChar(bytes[6], bytes[7]);
        packet.payload = Arrays.copyOfRange(bytes, 8, bytes.length);
        return packet;
    }

    private char sourcePort;
    private char destinationPort;
    private char length;
    private char checksum;
    private byte[] payload;

    public char getSourcePort() {
        return sourcePort;
    }

    public UdpPacket sourcePort(final char sourcePort) {
        this.sourcePort = sourcePort;
        return this;
    }

    public char getDestinationPort() {
        return destinationPort;
    }

    public UdpPacket destinationPort(final char destinationPort) {
        this.destinationPort = destinationPort;
        return this;
    }

    public char getLength() {
        return length;
    }

    public UdpPacket length(final char length) {
        this.length = length;
        return this;
    }

    public char getChecksum() {
        return checksum;
    }

    public UdpPacket checksum(final char checksum) {
        this.checksum = checksum;
        return this;
    }

    public byte[] getPayload() {
        return payload;
    }

    public UdpPacket payload(final byte[] payload) {
        this.payload = payload;
        return this;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof UdpPacket)) return false;
        final UdpPacket tcpPacket = (UdpPacket) o;
        return getSourcePort() == tcpPacket.getSourcePort() &&
                getDestinationPort() == tcpPacket.getDestinationPort() &&
                getLength() == tcpPacket.getLength() &&
                getChecksum() == tcpPacket.getChecksum() &&
                Arrays.equals(getPayload(), tcpPacket.getPayload());
    }

    public int getPayloadLength() {
        return payload.length;
    }

    /**
     * Returns {@code true} if the source or destination port is either {@code 67} or {@code 68} and payload is not empty.
     *
     * @return {@code true} if the source or destination port is is either {@code 67} or {@code 68} and payload is not empty
     */
    public boolean hasDhcpPacket() {
        return (sourcePort == 67 || sourcePort == 68 || destinationPort == 67 || destinationPort == 68) && getPayloadLength() > 0;
    }

    /**
     * Returns {@code true} if the source or destination port is {@code 1813} and payload is not empty.
     *
     * @return {@code true} if the source or destination port is {@code 1813} and payload is not empty
     */
    public boolean hasRadiusAccounting() {
        return (sourcePort == 1813 || destinationPort == 1813) && getPayloadLength() > 0;
    }

    /**
     * Returns {@code true} if the source or destination port is {@code 1812} and payload is not empty.
     *
     * @return {@code true} if the source or destination port is {@code 1812} and payload is not empty
     */
    public boolean hasRadiusAuthentication() {
        return (sourcePort == 1812 || destinationPort == 1812) && getPayloadLength() > 0;
    }
}
