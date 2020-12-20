package com.probendi.libcap;

import java.text.ParseException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import org.jetbrains.annotations.Contract;

import static com.probendi.libcap.Parser.readChar;
import static com.probendi.libcap.Parser.readInt;
import static com.probendi.libcap.Parser.readNullTerminatedString;
import static com.probendi.libcap.Validator.validateObject;

/**
 * A DHCPv4 packet.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class DhcpPacket {

    static final byte[] MAGIC_COOKIE = new byte[]{(byte) 0x63, (byte) 0x82, (byte) 0x53, (byte) 0x63};

    /**
     * A DHCP packet's message type.
     */
    public enum MessageType {

        DHCP_DISCOVER(1),
        DHCP_OFFER(2),
        DHCP_REQUEST(3),
        DHCP_DECLINE(4),
        DHCP_ACK(5),
        DHCP_NACK(6),
        DHCP_RELEASE(7),
        DHCP_INFORM(8);

        private final byte type;

        MessageType(final int type) {
            this.type = (byte) type;
        }

        @Contract(pure = true)
        public byte getMessageType() {
            return type;
        }

        /**
         * Returns the message type for the given byte.
         *
         * @param b the byte
         * @return the operation for the given byte
         * @throws ParseException if the byte cannot be parsed
         */
        public static MessageType parse(final byte b) throws ParseException {
            for (final MessageType type : MessageType.values()) {
                if (type.getMessageType() == b)
                    return type;
            }
            throw new ParseException("invalid message type", b);
        }
    }

    /**
     * A DHCP packet's operation.
     */
    public enum Operation {

        BOOT_REQUEST(1),
        BOOT_REPLY(2);

        private final byte operation;

        Operation(final int operation) {
            this.operation = (byte) operation;
        }

        @Contract(pure = true)
        public byte getOperation() {
            return operation;
        }

        /**
         * Returns the operation for the given byte.
         *
         * @param b the byte
         * @return the operation for the given byte
         * @throws ParseException if the byte cannot be parsed
         */
        public static Operation parse(final byte b) throws ParseException {
            for (final Operation operation : Operation.values()) {
                if (operation.getOperation() == b)
                    return operation;
            }
            throw new ParseException("invalid operation", b);
        }
    }

    /**
     * Parses a DHCP packet from the given bytes.
     *
     * @param bytes the bytes to be parsed
     * @return a DhcpPacket packet
     * @throws IllegalArgumentException if {@code bytes} is not set
     * @throws ParseException           if the byte cannot be parsed
     */
    public static DhcpPacket parse(final byte[] bytes) throws ParseException {
        validateObject("bytes", bytes);
        final DhcpPacket packet = new DhcpPacket();
        int i = 0;
        packet.operation = Operation.parse(bytes[i++]);
        packet.htype = bytes[i++];
        packet.hlen = bytes[i++];
        packet.hops = bytes[i++];
        packet.xid = readInt(bytes[i++], bytes[i++], bytes[i++], bytes[i++]);
        packet.secs = readChar(bytes[i++], bytes[i++]);
        packet.flags = readChar(bytes[i++], bytes[i++]);
        packet.ciaddr = Arrays.copyOfRange(bytes, i, i = i + 4);
        packet.yiaddr = Arrays.copyOfRange(bytes, i, i = i + 4);
        packet.siaddr = Arrays.copyOfRange(bytes, i, i = i + 4);
        packet.giaddr = Arrays.copyOfRange(bytes, i, i = i + 4);
        packet.chaddr = Arrays.copyOfRange(bytes, i, i = i + 16);
        packet.sname = readNullTerminatedString(Arrays.copyOfRange(bytes, i, i = i + 64));
        packet.file = readNullTerminatedString(Arrays.copyOfRange(bytes, i, i = i + 128));
        packet.magicCookie = Arrays.copyOfRange(bytes, i, i = i + 4);
        if (!Arrays.equals(MAGIC_COOKIE, packet.magicCookie)) {
            throw new IllegalArgumentException("invalid magic cookie: " + Parser.bytesToString(packet.magicCookie));
        }
        final List<byte[]> options = new LinkedList<>();
        while (bytes[i] != (byte) 0xff) {
            final Option option = Option.parse(Arrays.copyOfRange(bytes, i, i + bytes[i + 1] + 2));
            if (option.getCode() == (byte) 0x35) {
                packet.messageType(MessageType.parse(option.getValue()[0]));
            }
            packet.options.add(option);
            i += bytes[i + 1] + 2;
        }
        return packet;
    }

    private Operation operation;
    private byte htype;
    private byte hlen;
    private byte hops;
    private int xid;
    private char secs;
    private char flags;
    private byte[] ciaddr;
    private byte[] yiaddr;
    private byte[] siaddr;
    private byte[] giaddr;
    private byte[] chaddr; // 16 octets
    private String sname; // 64 octets
    private String file; // 128 octets
    private byte[] magicCookie;
    private List<Option> options = new LinkedList<>();
    private MessageType messageType;

    public Operation getOperation() {
        return operation;
    }

    public DhcpPacket operation(final Operation op) {
        this.operation = op;
        return this;
    }

    public byte getHtype() {
        return htype;
    }

    public DhcpPacket htype(final byte htype) {
        this.htype = htype;
        return this;
    }

    public byte getHlen() {
        return hlen;
    }

    public DhcpPacket hlen(final byte hlen) {
        this.hlen = hlen;
        return this;
    }

    public byte getHops() {
        return hops;
    }

    public DhcpPacket hops(final byte hops) {
        this.hops = hops;
        return this;
    }

    public int getXid() {
        return xid;
    }

    public DhcpPacket xid(final int xid) {
        this.xid = xid;
        return this;
    }

    public char getSecs() {
        return secs;
    }

    public DhcpPacket secs(final char secs) {
        this.secs = secs;
        return this;
    }

    public char getFlags() {
        return flags;
    }

    public DhcpPacket flags(final char flags) {
        this.flags = flags;
        return this;
    }

    public byte[] getCiaddr() {
        return ciaddr;
    }

    public DhcpPacket ciaddr(final byte[] ciaddr) {
        this.ciaddr = ciaddr;
        return this;
    }

    public byte[] getYiaddr() {
        return yiaddr;
    }

    public DhcpPacket yiaddr(final byte[] yiaddr) {
        this.yiaddr = yiaddr;
        return this;
    }

    public byte[] getSiaddr() {
        return siaddr;
    }

    public DhcpPacket siaddr(final byte[] siaddr) {
        this.siaddr = siaddr;
        return this;
    }

    public byte[] getGiaddr() {
        return giaddr;
    }

    public DhcpPacket giaddr(final byte[] giaddr) {
        this.giaddr = giaddr;
        return this;
    }

    public byte[] getChaddr() {
        return chaddr;
    }

    public DhcpPacket chaddr(final byte[] chaddr) {
        this.chaddr = chaddr;
        return this;
    }

    public String getSname() {
        return sname;
    }

    public DhcpPacket sname(final String sname) {
        this.sname = sname;
        return this;
    }

    public String getFile() {
        return file;
    }

    public DhcpPacket file(final String file) {
        this.file = file;
        return this;
    }

    public byte[] getMagicCookie() {
        return magicCookie;
    }

    public DhcpPacket magicCookie(final byte[] magicCookie) {
        this.magicCookie = magicCookie;
        return this;
    }

    public List<Option> getOptions() {
        return options;
    }

    public DhcpPacket options(final List<Option> options) {
        this.options = options;
        return this;
    }

    public MessageType getMessageType() {
        return messageType;
    }

    public DhcpPacket messageType(final MessageType messageType) {
        this.messageType = messageType;
        return this;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof DhcpPacket)) return false;
        final DhcpPacket that = (DhcpPacket) o;
        return getHtype() == that.getHtype() &&
                getHlen() == that.getHlen() &&
                getHops() == that.getHops() &&
                getXid() == that.getXid() &&
                getSecs() == that.getSecs() &&
                getFlags() == that.getFlags() &&
                getOperation() == that.getOperation() &&
                Arrays.equals(getCiaddr(), that.getCiaddr()) &&
                Arrays.equals(getYiaddr(), that.getYiaddr()) &&
                Arrays.equals(getSiaddr(), that.getSiaddr()) &&
                Arrays.equals(getGiaddr(), that.getGiaddr()) &&
                Arrays.equals(getChaddr(), that.getChaddr()) &&
                Objects.equals(getSname(), that.getSname()) &&
                Objects.equals(getFile(), that.getFile()) &&
                Arrays.equals(getMagicCookie(), that.getMagicCookie()) &&
                Objects.equals(getOptions(), that.getOptions()) &&
                getMessageType() == that.getMessageType();
    }

    /**
     * An option.
     */
    public static class Option {

        /**
         * Parses an option from the given bytes.
         *
         * @param bytes the bytes to be parsed
         * @return a VSA
         * @throws IllegalArgumentException if {@code bytes} is not set
         */
        public static Option parse(final byte[] bytes) {
            validateObject("bytes", bytes);
            final Option packet = new Option();
            packet.code = bytes[0];
            packet.length = bytes[1];
            packet.value = Arrays.copyOfRange(bytes, 2, 2 + packet.length);
            return packet;
        }

        private byte code;
        private byte length;
        private byte[] value;

        public byte getCode() {
            return code;
        }

        public Option code(final byte code) {
            this.code = code;
            return this;
        }

        public byte getLength() {
            return length;
        }

        public Option length(final byte length) {
            this.length = length;
            return this;
        }

        public byte[] getValue() {
            return value;
        }

        public Option value(final byte[] value) {
            this.value = value;
            return this;
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) return true;
            if (!(o instanceof Option)) return false;
            final Option that = (Option) o;
            return getCode() == that.getCode() &&
                    getLength() == that.getLength() &&
                    Arrays.equals(getValue(), that.getValue());
        }
    }
}
