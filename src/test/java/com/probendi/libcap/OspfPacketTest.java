package com.probendi.libcap;

import java.text.ParseException;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class OspfPacketTest {

    @Test
    public void testParse() throws Exception {
        final String header = "02010030ac10240200000000ae6800000000000000000000";
        final String payload = "fffffffc000a020000000028ac10240100000000ac110101";

        final OspfPacket expected = new OspfPacket().version((byte) 2).type(OspfPacket.Type.HELLO).length((char) 48)
                .routerId(ParserTest.stringToBytes("ac102402")).areaId(ParserTest.stringToBytes("00000000")).checksum((char) 44648)
                .auType(OspfPacket.AuType.NO_AUTHENTICATION).authentication(new byte[]{0, 0, 0, 0, 0, 0, 0, 0})
                .payload(ParserTest.stringToBytes(payload));

        final OspfPacket actual = OspfPacket.parse(ParserTest.stringToBytes(header + payload));
        Assert.assertEquals(actual, expected);
    }

    // Negative test cases

    @Test(expectedExceptions = ParseException.class, expectedExceptionsMessageRegExp = "invalid type")
    public void testParseFails() throws Exception {
        final String header = "02990030ac10240200000000ae6800000000000000000000";
        final String payload = "fffffffc000a020000000028ac10240100000000ac110101";

        OspfPacket.parse(ParserTest.stringToBytes(header + payload));
    }
}