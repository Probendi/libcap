package com.probendi.libcap;

import org.testng.Assert;
import org.testng.annotations.Test;

import static com.probendi.libcap.ParserTest.stringToBytes;

/**
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class Dot1QPacketTest {

    @Test
    public void testParse() {
        final String header = "01005e000005001101000001810000240800";
        final String payload = "45c0004029b7400001599ed6ac102402e00000050201002cc0000001000000003ba2000000" +
                "00000000000000fffffffc000a0200000000280000000000000000";

        final Dot1QPacket expected = new Dot1QPacket().priority((byte) 0).dei(false).id((char) 36)
                .type(PacketType.IPv4).payload(stringToBytes(payload));

        final Record record = new Record().bytes(stringToBytes(header + payload));
        final Dot1QPacket actual = Dot1QPacket.parse(record);
        Assert.assertEquals(actual, expected);
        Assert.assertTrue(actual.hasIpv4());
        Assert.assertFalse(actual.hasIpv6());
        Assert.assertFalse(actual.hasPppoEDiscoveryPacket());
        Assert.assertFalse(actual.hasPppoESessionPacket());
    }
}