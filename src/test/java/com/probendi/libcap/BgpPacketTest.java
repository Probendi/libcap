package com.probendi.libcap;

import java.text.ParseException;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class BgpPacketTest {

    @Test
    public void testParse() throws Exception {
        final String header = "ffffffffffffffffffffffffffffffff001705";
        final String payload = "00010080";

        final BgpPacket expected = new BgpPacket().marker(ParserTest.stringToBytes("ffffffffffffffffffffffffffffffff"))
                .length((char) 23).payload(ParserTest.stringToBytes(payload)).type(BgpPacket.Type.ROUTE_REFRESH);

        final BgpPacket actual = BgpPacket.parse(ParserTest.stringToBytes(header + payload));
        Assert.assertEquals(actual, expected);
        Assert.assertEquals(actual.getPayloadLength(), payload.length() / 2);
    }

    // Negative test cases

    @Test(expectedExceptions = ParseException.class, expectedExceptionsMessageRegExp = "invalid type")
    public void testParseFails() throws Exception {
        BgpPacket.parse(ParserTest.stringToBytes("ffffffffffffffffffffffffffffffff0017ff00010080"));
    }
}