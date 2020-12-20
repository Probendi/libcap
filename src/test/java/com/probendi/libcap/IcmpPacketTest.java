package com.probendi.libcap;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class IcmpPacketTest {

    @Test
    public void testParse() {
        final String header = "0303026100000000";
        final String payload = "450000e20000000001115eb80a2a000128282801003f003f00cef94f";

        final IcmpPacket expected = new IcmpPacket().type((byte) 3).code((byte) 3).checksum((char) 0x0261)
                .restOfHeader(0).data(ParserTest.stringToBytes(payload));

        final IcmpPacket actual = IcmpPacket.parse(ParserTest.stringToBytes(header + payload));
        Assert.assertEquals(actual, expected);
    }
}