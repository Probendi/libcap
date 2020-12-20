package com.probendi.libcap;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class Ipv6PacketTest {

    @Test
    public void testParse() {
        final String header = "6000000000ba1101fd00001000420000000100000000000100400000000000000000000000000001";
        final String payload = "003f003f00ba534decc0d6806f7683004978696100000000000102030405060708090a0b0c" +
                "0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40" +
                "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374" +
                "75767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091929394959697989967c900000082e8fb";

        final Ipv6Packet expected = new Ipv6Packet().trafficClass((byte) 0).flowLabel(0).length((char) 186)
                .nextHeader((byte) 17).hopLimit((byte) 1)
                .source(new byte[]{(byte) 0xfd, 0, 0, 0x10, 0, 0x42, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1})
                .destination(new byte[]{(byte) 0, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
                .payload(ParserTest.stringToBytes(payload));

        final Ipv6Packet actual = Ipv6Packet.parse(ParserTest.stringToBytes(header + payload));
        Assert.assertEquals(actual, expected);
        Assert.assertEquals(actual.getPayloadLength(), payload.length() / 2);
        Assert.assertFalse(actual.hasIcmpv6());
        Assert.assertFalse(actual.hasTcp());
        Assert.assertTrue(actual.hasUdp());
    }
}