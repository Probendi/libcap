package com.probendi.libcap;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class UdpPacketTest {

    @Test
    public void testParse() {
        final String header = "c3500714010cc419";
        final String payload = "015701042ae0841c195193c2cb32eea3cdced9d7010e73696e676c652d737461636b0212ff850dcb9b84" +
                "559ce5d5e92c983e98fe05060600b0650406ac1101010606000000020706000000011f1330303a31313a30313a30303a303" +
                "03a3031200658382d323d060000000f571758382d322065746820302f362f302f31313a3130312c2058382d323036303131" +
                "3031303130303030303932623639323030323030304d0c313030303030303030301a56000007db3b065b4329e73c2332353" +
                "52e3235352e3235352e3235352030303a31313a30313a30303a30303a30311a0600002000fe0b487561776569204e45ff04" +
                "4e458a12696e7465726e65742e6b706e2e636f6d";

        final UdpPacket expected = new UdpPacket().sourcePort((char) 50000).destinationPort((char) 1812)
                .length((char) 268).checksum((char) 0xc419).payload(ParserTest.stringToBytes(payload));


        final UdpPacket actual = UdpPacket.parse(ParserTest.stringToBytes(header + payload));
        Assert.assertEquals(actual, expected);
        Assert.assertEquals(actual.getPayloadLength(), payload.length() / 2);
        Assert.assertFalse(actual.hasRadiusAccounting());
        Assert.assertTrue(actual.hasRadiusAuthentication());
    }
}