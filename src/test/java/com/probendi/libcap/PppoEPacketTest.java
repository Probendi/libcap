package com.probendi.libcap;

import java.text.ParseException;

import org.testng.Assert;
import org.testng.annotations.Test;

import static com.probendi.libcap.ParserTest.stringToBytes;

/**
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class PppoEPacketTest {

    @Test
    public void testParseDiscovery() throws Exception {

        final String header = "110900000004";
        final String payload = "01010000";

        final PppoEPacket expected = new PppoEPacket().version((byte) 1).type((byte) 1).length((char) 4)
                .code(PppoEPacket.Code.PADI).sessionId((char) 0).payload(stringToBytes(payload));

        final PppoEPacket actual = PppoEPacket.parse(stringToBytes(header + payload));
        Assert.assertEquals(actual, expected);
    }

    @Test
    public void testParseSession() throws Exception {
        final String header = "1100009e003a0021";
        final String payload = "45000038004a0000ff016127282828010a2a00010303026100000000450000e20000" +
                "000001115eb80a2a000128282801003f003f00cef94f";

        final PppoEPacket expected = new PppoEPacket().version((byte) 1).type((byte) 1).length((char) 58)
                .code(PppoEPacket.Code.SESSION_STAGE).sessionId((char) 0x9e)
                .pointToPointProtocol(PppoEPacket.PointToPointProtocol.IPV4).payload(stringToBytes(payload));

        final PppoEPacket actual = PppoEPacket.parse(stringToBytes(header + payload));
        Assert.assertEquals(actual, expected);
        Assert.assertTrue(actual.hasIpv4());
        Assert.assertFalse(actual.hasIpv6());
    }

    // Negative test cases

    @Test(expectedExceptions = ParseException.class, expectedExceptionsMessageRegExp = "invalid code")
    public void testParseCodeFails() throws Exception {
        final String header = "1188009e003a0021";
        final String payload = "45000038004a0000ff016127282828010a2a00010303026100000000450000e20000" +
                "000001115eb80a2a000128282801003f003f00cef94f";

        PppoEPacket.parse(stringToBytes(header + payload));
    }

    @Test(expectedExceptions = ParseException.class, expectedExceptionsMessageRegExp = "invalid protocol")
    public void testUnsupportedProtocol() throws Exception {
        final String header = "1100009e003a9999";
        final String payload = "45000038004a0000ff016127282828010a2a00010303026100000000450000e20000" +
                "000001115eb80a2a000128282801003f003f00cef94f";

        PppoEPacket.parse(stringToBytes(header + payload));
    }
}