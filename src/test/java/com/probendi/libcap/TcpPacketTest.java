package com.probendi.libcap;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class TcpPacketTest {

    @Test
    public void testParse() {
        final String header = "00b3ea1f93db493600010b10a01821fc14b30000";
        final String options = "01011312c9252954b5c64b06d98eaabdae38bbe7";
        final String payload = "ffffffffffffffffffffffffffffffff001304";

        final TcpPacket expected = new TcpPacket().sourcePort((char) 179).destinationPort((char) 59935)
                .sequenceNumber(0x93db4936).acknowledgmentNumber(0x10b10).dataOffset((byte) 10).ns(false)
                .cwr(false).ece(false).urg(false).ack(true).psh(true).rst(false).syn(false)
                .fin(false).windowsSize((char) 0x21fc).checksum((char) 0x14b3).urgentPointer((char) 0)
                .options(ParserTest.stringToBytes(options)).payload(ParserTest.stringToBytes(payload));


        final TcpPacket actual = TcpPacket.parse(ParserTest.stringToBytes(header + options + payload));
        Assert.assertEquals(actual, expected);
        Assert.assertEquals(actual.getOptionsLength(), options.length() / 2);
        Assert.assertEquals(actual.getPayloadLength(), payload.length() / 2);
        Assert.assertTrue(actual.hasBgp());
    }
}