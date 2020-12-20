package com.probendi.libcap;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class Ipv4PacketTest {

    @Test
    public void testParse() {
        final String header = "450004f600000000403d439d0a2a000128020002";
        final String payload = "9a106ee3c5b583094978696000000000101112130174237304c61a1b1c1d1e1f202122232" +
                "425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051525354555657" +
                "58595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8" +
                "b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbe" +
                "bfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f" +
                "2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425" +
                "262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051525354555657585" +
                "95a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c" +
                "8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc" +
                "0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3" +
                "f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262" +
                "728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a" +
                "5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8" +
                "e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1" +
                "c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f" +
                "5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728" +
                "292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5" +
                "c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f" +
                "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c" +
                "3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6" +
                "f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292" +
                "a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d" +
                "5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909" +
                "192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4" +
                "c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf7441";

        final Ipv4Packet expected = new Ipv4Packet().ihl((byte) 5).dscp((byte) 0).ecn((byte) 0)
                .length((char) 1270).identification((char) 0).flags((byte) 0).fragmentOffset((char) 0)
                .ttl((byte) 64).protocol((byte) 61).checksum((char) 0x439d).source(new byte[]{10, 42, 0, 1})
                .destination(new byte[]{40, 2, 0, 2}).options(new byte[]{}).payload(ParserTest.stringToBytes(payload))
                .payload(ParserTest.stringToBytes(payload));

        final Ipv4Packet actual = Ipv4Packet.parse(ParserTest.stringToBytes(header + payload));
        Assert.assertEquals(actual, expected);
        Assert.assertEquals(actual.getPayloadLength(), payload.length() / 2);
        Assert.assertFalse(actual.isFragmented());
        Assert.assertFalse(actual.hasOptions());
        Assert.assertFalse(actual.hasIcmp());
        Assert.assertFalse(actual.hasTcp());
        Assert.assertFalse(actual.hasUdp());
        Assert.assertFalse(actual.hasOspf());
    }

    @Test
    public void testParseWithDscp() {
        final String header = "45c0006a000000003e3d496a280200010a2a0001";
        final String payload = "9a106ee3c5b5830949786960000000001011121302e65203003a1a1b1c1d1e1f202122232425262728292a" +
                "2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152532595";

        final Ipv4Packet expected = new Ipv4Packet().ihl((byte) 5).dscp((byte) 0x30).ecn((byte) 0)
                .length((char) 106).identification((char) 0).flags((byte) 0).fragmentOffset((char) 0)
                .ttl((byte) 62).protocol((byte) 61).checksum((char) 0x496a).source(new byte[]{40, 2, 0, 1})
                .destination(new byte[]{10, 42, 0, 1}).options(new byte[]{}).payload(ParserTest.stringToBytes(payload))
                .payload(ParserTest.stringToBytes(payload));

        final Ipv4Packet actual = Ipv4Packet.parse(ParserTest.stringToBytes(header + payload));
        Assert.assertEquals(actual, expected);
        Assert.assertEquals(actual.getPayloadLength(), payload.length() / 2);
        Assert.assertFalse(actual.isFragmented());
        Assert.assertFalse(actual.hasOptions());
        Assert.assertFalse(actual.hasIcmp());
        Assert.assertFalse(actual.hasTcp());
        Assert.assertFalse(actual.hasUdp());
        Assert.assertFalse(actual.hasOspf());
    }
}