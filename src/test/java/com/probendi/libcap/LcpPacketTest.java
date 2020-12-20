package com.probendi.libcap;

import java.text.ParseException;

import org.testng.Assert;
import org.testng.annotations.Test;

import static com.probendi.libcap.ParserTest.stringToBytes;

public class LcpPacketTest {

    @Test
    public void testParse() throws Exception {
        final String header = "01010012";
        final String payload = "010405dc0304c0230506ce9e024a";

        final LcpPacket expected = new LcpPacket().code(LcpPacket.Code.CONFIGURE_REQUEST).identifier((byte) 1)
                .length((char) 18).data(stringToBytes(payload));

        final LcpPacket actual = LcpPacket.parse(stringToBytes(header + payload));
        Assert.assertEquals(actual, expected);
    }

    // Negative test cases

    @Test(expectedExceptions = ParseException.class, expectedExceptionsMessageRegExp = "invalid code")
    public void testParseCodeFails() throws Exception {
        final String header = "57010012";
        final String payload = "010405dc0304c0230506ce9e024a";

        LcpPacket.parse(stringToBytes(header + payload));
    }
}