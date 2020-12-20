package com.probendi.libcap;

import java.text.ParseException;
import java.util.LinkedList;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.Test;

import static com.probendi.libcap.DhcpPacket.MAGIC_COOKIE;
import static com.probendi.libcap.DhcpPacket.MessageType.DHCP_OFFER;
import static com.probendi.libcap.DhcpPacket.Operation.BOOT_REPLY;
import static com.probendi.libcap.ParserTest.stringToBytes;

public class DhcpPacketTest {

    @Test
    public void testParse() throws Exception {
        final String bytes = "020106005b5c276f0000000000000000640a000200000000640a0001001101000001000000000000000000" +
                "004142430000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006382536335" +
                "01023604640100013304000002580104ffffff003a040000012c3b040000020d5219011758382d32207472756e6b20302f3" +
                "02f322f31303a323130ff";

        final List<DhcpPacket.Option> options = new LinkedList<>();
        options.add(new DhcpPacket.Option().code((byte) 53).length((byte) 1).value(stringToBytes("02")));

        options.add(new DhcpPacket.Option().code((byte) 54).length((byte) 4).value(stringToBytes("64010001")));

        options.add(new DhcpPacket.Option().code((byte) 51).length((byte) 4).value(stringToBytes("00000258")));

        options.add(new DhcpPacket.Option().code((byte) 1).length((byte) 4).value(stringToBytes("ffffff00")));

        options.add(new DhcpPacket.Option().code((byte) 58).length((byte) 4).value(stringToBytes("0000012c")));

        options.add(new DhcpPacket.Option().code((byte) 59).length((byte) 4).value(stringToBytes("0000020d")));

        options.add(new DhcpPacket.Option().code((byte) 82).length((byte) 0x19)
                .value(stringToBytes("011758382d32207472756e6b20302f302f322f31303a323130")));

        final DhcpPacket expected = new DhcpPacket().operation(BOOT_REPLY)
                .htype((byte) 1).hlen((byte) 6).hops((byte) 0).xid(0x5b5c276f).secs((char) 0).flags((char) 0)
                .ciaddr(stringToBytes("00000000")).yiaddr(stringToBytes("640a0002"))
                .siaddr(stringToBytes("00000000")).giaddr(stringToBytes("640a0001"))
                .chaddr(stringToBytes("00110100000100000000000000000000"))
                .sname("ABC").file("").magicCookie(MAGIC_COOKIE).options(options).messageType(DHCP_OFFER);

        final DhcpPacket actual = DhcpPacket.parse(stringToBytes(bytes));
        Assert.assertEquals(actual, expected);
    }

    // Negative test cases

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "invalid magic cookie: 0x63885363")
    public void testParseFails() throws Exception {
        final String bytes = "020106005b5c276f0000000000000000640a000200000000640a0001001101000001000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006388536335" +
                "01023604640100013304000002580104ffffff003a040000012c3b040000020d5219011758382d32207472756e6b20302f3" +
                "02f322f31303a323130ff";

        DhcpPacket.parse(stringToBytes(bytes));
    }

    @Test(expectedExceptions = ParseException.class, expectedExceptionsMessageRegExp = "invalid message type")
    public void testParseMessageTypeFails() throws Exception {
        final String bytes = "020106005b5c276f0000000000000000640a000200000000640a0001001101000001000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006382536335" +
                "01ff3604640100013304000002580104ffffff003a040000012c3b040000020d5219011758382d32207472756e6b20302f3" +
                "02f322f31303a323130ff";

        DhcpPacket.parse(stringToBytes(bytes));
    }

    @Test(expectedExceptions = ParseException.class, expectedExceptionsMessageRegExp = "invalid operation")
    public void testParseOperationFails() throws Exception {
        final String bytes = "000106005b5c276f0000000000000000640a000200000000640a0001001101000001000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006382536335" +
                "01023604640100013304000002580104ffffff003a040000012c3b040000020d5219011758382d32207472756e6b20302f3" +
                "02f322f31303a323130ff";

        DhcpPacket.parse(stringToBytes(bytes));
    }
}