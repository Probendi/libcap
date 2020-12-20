package com.probendi.libcap;

import org.jetbrains.annotations.Contract;

/**
 * A packet type (see https://en.wikipedia.org/wiki/EtherType).
 */
public enum PacketType {
    IPv4(0x0800),
    DOT1Q(0x8100),
    IPv6(0x86DD),
    MPLS(0x8847),
    PPPoE_DISC(0x8863),
    PPPoE_SESS(0x8864),
    UNSUPPORTED(0);

    private char type;

    PacketType(final int type) {
        this.type = (char) type;
    }

    @Contract(pure = true)
    public char getType() {
        return type;
    }

    /**
     * Returns the packet type for the given bytes.
     *
     * @param b0 the most significant byte
     * @param b1 the least significant byte
     * @return the packet type for the given bytes
     */
    public static PacketType parse(final byte b0, final byte b1) {
        return parse(Parser.readChar(b0, b1));
    }

    /**
     * Returns the packet type for the given char.
     *
     * @param c the char
     * @return the packet type for the given char
     */
    public static PacketType parse(final char c) {
        for (final PacketType type : PacketType.values()) {
            if (type.getType() == c)
                return type;
        }
        return PacketType.UNSUPPORTED;
    }
}
