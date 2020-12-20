package com.probendi.libcap;

import java.util.Arrays;
import java.util.Objects;

import static com.probendi.libcap.Validator.validateObject;

/**
 * An IPv6 packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class Ipv6Packet {

    /**
     * Parses an IPv6 packet from the given bytes.
     *
     * @param bytes the bytes to be parsed
     * @return an IPv6 packet
     * @throws IllegalArgumentException if {@code bytes} is not not set
     */
    public static Ipv6Packet parse(final byte[] bytes) {
        validateObject("bytes", bytes);
        final Ipv6Packet packet = new Ipv6Packet();
        packet.trafficClass = (byte) ((char) (Parser.readChar(bytes[0], bytes[1]) & (char) 0xff0) >> 4);
        packet.flowLabel = Parser.readInt((byte) 0, bytes[1], bytes[2], bytes[3]) & 0xfffff;
        packet.length = Parser.readChar(bytes[4], bytes[5]);
        packet.nextHeader = bytes[6];
        packet.hopLimit = bytes[7];
        packet.source = Arrays.copyOfRange(bytes, 8, 24);
        packet.destination = Arrays.copyOfRange(bytes, 24, 40);
        packet.payload = Arrays.copyOfRange(bytes, 40, bytes.length);
        return packet;
    }

    private byte trafficClass;
    private int flowLabel;
    private char length;
    private byte nextHeader;
    private byte hopLimit;
    private byte[] source;
    private byte[] destination;
    private byte[] payload;

    public byte getTrafficClass() {
        return trafficClass;
    }

    public Ipv6Packet trafficClass(final byte trafficClass) {
        this.trafficClass = trafficClass;
        return this;
    }

    public int getFlowLabel() {
        return flowLabel;
    }

    public Ipv6Packet flowLabel(final int flowLabel) {
        this.flowLabel = flowLabel;
        return this;
    }

    public char getLength() {
        return length;
    }

    public Ipv6Packet length(final char length) {
        this.length = length;
        return this;
    }

    public byte getNextHeader() {
        return nextHeader;
    }

    public Ipv6Packet nextHeader(final byte nextHeader) {
        this.nextHeader = nextHeader;
        return this;
    }

    public byte getHopLimit() {
        return hopLimit;
    }

    public Ipv6Packet hopLimit(final byte hopLimit) {
        this.hopLimit = hopLimit;
        return this;
    }

    public String getSource() {
        return Parser.bytesToString(source);
    }

    public Ipv6Packet source(final byte[] source) {
        this.source = source;
        return this;
    }

    public String getDestination() {
        return Parser.bytesToString(destination);
    }

    public Ipv6Packet destination(final byte[] destination) {
        this.destination = destination;
        return this;
    }

    public byte[] getPayload() {
        return payload;
    }

    public Ipv6Packet payload(final byte[] payload) {
        this.payload = payload;
        return this;
    }

    public int getPayloadLength() {
        return payload.length;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof Ipv6Packet)) return false;
        final Ipv6Packet that = (Ipv6Packet) o;
        return getTrafficClass() == that.getTrafficClass() &&
                getFlowLabel() == that.getFlowLabel() &&
                getLength() == that.getLength() &&
                getNextHeader() == that.getNextHeader() &&
                getHopLimit() == that.getHopLimit() &&
                Objects.equals(getSource(), that.getSource()) &&
                Objects.equals(getDestination(), that.getDestination()) &&
                Arrays.equals(getPayload(), that.getPayload());
    }

    /**
     * Returns {@code true} if this protocol encapsulates ICMPv6.
     *
     * @return {@code true} if this protocol encapsulates ICMPv6
     */
    public boolean hasIcmpv6() {
        return nextHeader == 58;
    }

    /**
     * Returns {@code true} if this protocol encapsulates TCP.
     *
     * @return {@code true} if this protocol encapsulates TCP
     */
    public boolean hasTcp() {
        return nextHeader == 6;
    }

    /**
     * Returns {@code true} if this protocol encapsulates UDP.
     *
     * @return {@code true} if this protocol encapsulates UDP
     */
    public boolean hasUdp() {
        return nextHeader == 0x11;
    }
}
