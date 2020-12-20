package com.probendi.libcap;

import java.util.Arrays;

/**
 * A TCP packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class TcpPacket {

    /**
     * Parses a TCP packet from the given bytes.
     *
     * @param bytes the bytes to be parsed
     * @return a TCP packet
     * @throws IllegalArgumentException if {@code bytes} is not not set
     */
    public static TcpPacket parse(final byte[] bytes) {
        Validator.validateObject("bytes", bytes);
        final TcpPacket packet = new TcpPacket();
        packet.sourcePort = Parser.readChar(bytes[0], bytes[1]);
        packet.destinationPort = Parser.readChar(bytes[2], bytes[3]);
        packet.sequenceNumber = Parser.readInt(bytes[4], bytes[5], bytes[6], bytes[7]);
        packet.acknowledgmentNumber = Parser.readInt(bytes[8], bytes[9], bytes[10], bytes[11]);
        packet.dataOffset = (byte) (bytes[12] >> 4 & 0xf);
        packet.ns = (bytes[12] & 1) == 1;
        packet.cwr = (bytes[13] & 0x80) == 0x80;
        packet.ece = (bytes[13] & 0x40) == 0x40;
        packet.urg = (bytes[13] & 0x20) == 0x20;
        packet.ack = (bytes[13] & 0x10) == 0x10;
        packet.psh = (bytes[13] & 8) == 8;
        packet.rst = (bytes[13] & 4) == 4;
        packet.syn = (bytes[13] & 2) == 2;
        packet.fin = (bytes[13] & 1) == 1;
        packet.windowsSize = Parser.readChar(bytes[14], bytes[15]);
        packet.checksum = Parser.readChar(bytes[16], bytes[17]);
        packet.urgentPointer = Parser.readChar(bytes[18], bytes[19]);
        packet.options = Arrays.copyOfRange(bytes, 20, packet.dataOffset * 4);
        packet.payload = Arrays.copyOfRange(bytes, packet.dataOffset * 4, bytes.length);
        return packet;
    }

    private char sourcePort;
    private char destinationPort;
    private long sequenceNumber;
    private long acknowledgmentNumber;
    private byte dataOffset;
    private boolean ns;
    private boolean cwr;
    private boolean ece;
    private boolean urg;
    private boolean ack;
    private boolean psh;
    private boolean rst;
    private boolean syn;
    private boolean fin;
    private char windowsSize;
    private char checksum;
    private char urgentPointer;
    private byte[] options;
    private byte[] payload;

    public char getSourcePort() {
        return sourcePort;
    }

    public TcpPacket sourcePort(final char sourcePort) {
        this.sourcePort = sourcePort;
        return this;
    }

    public char getDestinationPort() {
        return destinationPort;
    }

    public TcpPacket destinationPort(final char destinationPort) {
        this.destinationPort = destinationPort;
        return this;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public TcpPacket sequenceNumber(final long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
        return this;
    }

    public long getAcknowledgmentNumber() {
        return acknowledgmentNumber;
    }

    public TcpPacket acknowledgmentNumber(final long acknowledgmentNumber) {
        this.acknowledgmentNumber = acknowledgmentNumber;
        return this;
    }

    public byte getDataOffset() {
        return dataOffset;
    }

    public TcpPacket dataOffset(final byte dataOffset) {
        this.dataOffset = dataOffset;
        return this;
    }

    public boolean isNs() {
        return ns;
    }

    public TcpPacket ns(final boolean ns) {
        this.ns = ns;
        return this;
    }

    public boolean isCwr() {
        return cwr;
    }

    public TcpPacket cwr(final boolean cwr) {
        this.cwr = cwr;
        return this;
    }

    public boolean isEce() {
        return ece;
    }

    public TcpPacket ece(final boolean ece) {
        this.ece = ece;
        return this;
    }

    public boolean isUrg() {
        return urg;
    }

    public TcpPacket urg(final boolean urg) {
        this.urg = urg;
        return this;
    }

    public boolean isAck() {
        return ack;
    }

    public TcpPacket ack(final boolean ack) {
        this.ack = ack;
        return this;
    }

    public boolean isPsh() {
        return psh;
    }

    public TcpPacket psh(final boolean psh) {
        this.psh = psh;
        return this;
    }

    public boolean isRst() {
        return rst;
    }

    public TcpPacket rst(final boolean rst) {
        this.rst = rst;
        return this;
    }

    public boolean isSyn() {
        return syn;
    }

    public TcpPacket syn(final boolean syn) {
        this.syn = syn;
        return this;
    }

    public boolean isFin() {
        return fin;
    }

    public TcpPacket fin(final boolean fin) {
        this.fin = fin;
        return this;
    }

    public char getWindowsSize() {
        return windowsSize;
    }

    public TcpPacket windowsSize(final char windowsSize) {
        this.windowsSize = windowsSize;
        return this;
    }

    public char getChecksum() {
        return checksum;
    }

    public TcpPacket checksum(final char checksum) {
        this.checksum = checksum;
        return this;
    }

    public char getUrgentPointer() {
        return urgentPointer;
    }

    public TcpPacket urgentPointer(final char urgentPointer) {
        this.urgentPointer = urgentPointer;
        return this;
    }

    public byte[] getOptions() {
        return options;
    }

    public TcpPacket options(final byte[] options) {
        this.options = options;
        return this;
    }

    public byte[] getPayload() {
        return payload;
    }

    public TcpPacket payload(final byte[] payload) {
        this.payload = payload;
        return this;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof TcpPacket)) return false;
        final TcpPacket tcpPacket = (TcpPacket) o;
        return getSourcePort() == tcpPacket.getSourcePort() &&
                getDestinationPort() == tcpPacket.getDestinationPort() &&
                getSequenceNumber() == tcpPacket.getSequenceNumber() &&
                getAcknowledgmentNumber() == tcpPacket.getAcknowledgmentNumber() &&
                getDataOffset() == tcpPacket.getDataOffset() &&
                isNs() == tcpPacket.isNs() &&
                isCwr() == tcpPacket.isCwr() &&
                isEce() == tcpPacket.isEce() &&
                isUrg() == tcpPacket.isUrg() &&
                isAck() == tcpPacket.isAck() &&
                isPsh() == tcpPacket.isPsh() &&
                isRst() == tcpPacket.isRst() &&
                isSyn() == tcpPacket.isSyn() &&
                isFin() == tcpPacket.isFin() &&
                getWindowsSize() == tcpPacket.getWindowsSize() &&
                getChecksum() == tcpPacket.getChecksum() &&
                getUrgentPointer() == tcpPacket.getUrgentPointer() &&
                Arrays.equals(getOptions(), tcpPacket.getOptions()) &&
                Arrays.equals(getPayload(), tcpPacket.getPayload());
    }

    public int getOptionsLength() {
        return options.length;
    }

    public int getPayloadLength() {
        return payload.length;
    }

    /**
     * Returns {@code true} if the source or destination port is {@code 179} and payload is not empty.
     *
     * @return {@code true} if the source or destination port is {@code 179} and payload is not empty
     */
    public boolean hasBgp() {
        return (sourcePort == 179 || destinationPort == 179) && getPayloadLength() > 0;
    }
}
