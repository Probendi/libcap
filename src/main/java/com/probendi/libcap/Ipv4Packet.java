package com.probendi.libcap;

import java.util.Arrays;
import java.util.Objects;

import static com.probendi.libcap.Validator.validateObject;

/**
 * An IPv4 packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class Ipv4Packet {

    /**
     * Parses an IPv4 packet from the given bytes.
     *
     * @param bytes the bytes to be parsed
     * @return an IPv4 packet
     * @throws IllegalArgumentException if {@code bytes} is not not set
     */
    public static Ipv4Packet parse(final byte[] bytes) {
        validateObject("bytes", bytes);
        final Ipv4Packet packet = new Ipv4Packet();
        packet.ihl = (byte) (bytes[0] & (byte) 0xf);
        packet.dscp = (byte) (bytes[1] >> 2 & (byte) 0x3f);
        packet.ecn = (byte) (bytes[1] & (byte) 0x3);
        packet.length = Parser.readChar(bytes[2], bytes[3]);
        packet.identification = Parser.readChar(bytes[4], bytes[5]);
        packet.flags = (byte) ((bytes[6] & (byte) 0xe0) >> 5);
        packet.fragmentOffset = (char) (Parser.readChar(bytes[6], bytes[7]) & (char) 0x1fff);
        packet.ttl = bytes[8];
        packet.protocol = bytes[9];
        packet.checksum = Parser.readChar(bytes[10], bytes[11]);
        packet.source = Arrays.copyOfRange(bytes, 12, 16);
        packet.destination = Arrays.copyOfRange(bytes, 16, 20);
        packet.options = packet.ihl > 0x20 ? Arrays.copyOfRange(bytes, 21, packet.ihl - 0x20) : new byte[]{};
        packet.payload = Arrays.copyOfRange(bytes, packet.ihl * 4, bytes.length);
        return packet;
    }

    private byte ihl;
    private byte dscp;
    private byte ecn;
    private char length;
    private char identification;
    private byte flags;
    private char fragmentOffset;
    private byte ttl;
    private byte protocol;
    private char checksum;
    private byte[] source;
    private byte[] destination;
    private byte[] options;
    private byte[] payload;

    public byte getIhl() {
        return ihl;
    }

    public Ipv4Packet ihl(final byte ihl) {
        this.ihl = ihl;
        return this;
    }

    public byte getDscp() {
        return dscp;
    }

    public Ipv4Packet dscp(final byte dscp) {
        this.dscp = dscp;
        return this;
    }

    public byte getEcn() {
        return ecn;
    }

    public Ipv4Packet ecn(final byte ecn) {
        this.ecn = ecn;
        return this;
    }

    public char getLength() {
        return length;
    }

    public Ipv4Packet length(final char length) {
        this.length = length;
        return this;
    }

    public char getIdentification() {
        return identification;
    }

    public Ipv4Packet identification(final char identification) {
        this.identification = identification;
        return this;
    }

    public byte getFlags() {
        return flags;
    }

    public Ipv4Packet flags(final byte flags) {
        this.flags = flags;
        return this;
    }

    public char getFragmentOffset() {
        return fragmentOffset;
    }

    public Ipv4Packet fragmentOffset(final char fragmentOffset) {
        this.fragmentOffset = fragmentOffset;
        return this;
    }

    public byte getTtl() {
        return ttl;
    }

    public Ipv4Packet ttl(final byte ttl) {
        this.ttl = ttl;
        return this;
    }

    public byte getProtocol() {
        return protocol;
    }

    public Ipv4Packet protocol(final byte protocol) {
        this.protocol = protocol;
        return this;
    }

    public char getChecksum() {
        return checksum;
    }

    public Ipv4Packet checksum(final char checksum) {
        this.checksum = checksum;
        return this;
    }

    public String getSource() {
        return Parser.bytesToString(source);
    }

    public Ipv4Packet source(final byte[] source) {
        this.source = source;
        return this;
    }

    public String getDestination() {
        return Parser.bytesToString(destination);
    }

    public Ipv4Packet destination(final byte[] destination) {
        this.destination = destination;
        return this;
    }

    public byte[] getOptions() {
        return options;
    }

    public Ipv4Packet options(final byte[] options) {
        this.options = options;
        return this;
    }

    public byte[] getPayload() {
        return payload;
    }

    public Ipv4Packet payload(final byte[] payload) {
        this.payload = payload;
        return this;
    }

    public int getPayloadLength() {
        return payload.length;
    }

    /**
     * Returns {@code true} if this packet has options.
     *
     * @return {@code true} if this packet has options
     */
    public boolean hasOptions() {
        return options.length > 0;
    }

    /**
     * Returns {@code true} if this packets is fragmented.
     *
     * @return {@code true} if this packets is fragmented
     */
    public boolean isFragmented() {
        return (flags & 0b1) == 1;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof Ipv4Packet)) return false;
        final Ipv4Packet that = (Ipv4Packet) o;
        return getIhl() == that.getIhl() &&
                getDscp() == that.getDscp() &&
                getEcn() == that.getEcn() &&
                getLength() == that.getLength() &&
                getIdentification() == that.getIdentification() &&
                getFlags() == that.getFlags() &&
                getFragmentOffset() == that.getFragmentOffset() &&
                getTtl() == that.getTtl() &&
                getProtocol() == that.getProtocol() &&
                getChecksum() == that.getChecksum() &&
                Objects.equals(getSource(), that.getSource()) &&
                Objects.equals(getDestination(), that.getDestination()) &&
                Arrays.equals(getOptions(), that.getOptions()) &&
                Arrays.equals(getPayload(), that.getPayload());
    }

    /**
     * Returns {@code true} if this protocol encapsulates ICMP.
     *
     * @return {@code true} if this protocol encapsulates ICMP
     */
    public boolean hasIcmp() {
        return protocol == 1;
    }

    /**
     * Returns {@code true} if this protocol encapsulates OSPF.
     *
     * @return {@code true} if this protocol encapsulates OSPF
     */
    public boolean hasOspf() {
        return protocol == 0x59;
    }

    /**
     * Returns {@code true} if this protocol encapsulates TCP.
     *
     * @return {@code true} if this protocol encapsulates TCP
     */
    public boolean hasTcp() {
        return protocol == 6;
    }

    /**
     * Returns {@code true} if this protocol encapsulates UDP.
     *
     * @return {@code true} if this protocol encapsulates UDP
     */
    public boolean hasUdp() {
        return protocol == 0x11;
    }
}
