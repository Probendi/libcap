package com.probendi.libcap;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class Icmpv6PacketTest {

    @Test
    public void testParse() {
        final String header = "01048f5100000000";
        final String payload = "6000000000ba1101fd00001000420000000100000000000100400000000000000000000000" +
                "000001003f003f00ba534decc0d6806f7683004978696100000000000102030405060708090a0b0c0d0e0f101112131415161718" +
                "191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c" +
                "4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80" +
                "8182838485868788898a8b8c8d8e8f9091929394959697989967c900000082e8fb";

        final Icmpv6Packet expected = new Icmpv6Packet().checksum((char) 0x8f51).type((byte) 1).code((byte) 4)
                .data(ParserTest.stringToBytes(payload));

        final Icmpv6Packet actual = Icmpv6Packet.parse(ParserTest.stringToBytes(header + payload));
        Assert.assertEquals(actual, expected);
    }
}