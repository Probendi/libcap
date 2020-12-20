package com.probendi.libcap;

import java.text.ParseException;
import java.util.LinkedList;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.Test;

import static com.probendi.libcap.ParserTest.stringToBytes;

public class RadiusPacketTest {

    @Test
    public void testParse() throws Exception {
        final String header = "015701042ae0841c195193c2cb32eea3cdced9d7";
        final String payload = "010e73696e676c652d737461636b0212ff850dcb9b84559ce5d5e92c983e98fe05060600b0650406ac110" +
                "1010606000000020706000000011f1330303a31313a30313a30303a30303a3031200658382d323d060000000f571758382d3" +
                "22065746820302f362f302f31313a3130312c2058382d3230363031313031303130303030303932623639323030323030304" +
                "d0c313030303030303030301a56000007db3b065b4329e73c233235352e3235352e3235352e3235352030303a31313a30313" +
                "a30303a30303a30311a0600002000fe0b487561776569204e45ff044e458a12696e7465726e65742e6b706e2e636f6d";

        final List<RadiusPacket.AttributeValuePair> attributeValuePairs = new LinkedList<>();
        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 1).length((byte) 14)
                .value(stringToBytes("73696e676c652d737461636b")));

        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 2).length((byte) 18)
                .value(stringToBytes("ff850dcb9b84559ce5d5e92c983e98fe")));

        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 5).length((byte) 6)
                .value(stringToBytes("0600b065")));

        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 4).length((byte) 6)
                .value(stringToBytes("ac110101")));

        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 6).length((byte) 6)
                .value(stringToBytes("00000002")));

        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 7).length((byte) 6)
                .value(stringToBytes("00000001")));

        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 31).length((byte) 19)
                .value(stringToBytes("30303a31313a30313a30303a30303a3031")));

        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 32).length((byte) 6)
                .value(stringToBytes("58382d32")));

        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 61).length((byte) 6)
                .value(stringToBytes("0000000f")));

        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 87).length((byte) 23)
                .value(stringToBytes("58382d322065746820302f362f302f31313a313031")));

        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 44).length((byte) 32)
                .value(stringToBytes("58382d323036303131303130313030303030393262363932303032303030")));

        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 77).length((byte) 12)
                .value(stringToBytes("31303030303030303030")));

        final List<RadiusPacket.VendorSpecificAttribute> vendorSpecificAttributes = new LinkedList<>();

        vendorSpecificAttributes.add(new RadiusPacket.VendorSpecificAttribute().type((byte) 59).length((byte) 6)
                .value(stringToBytes("5b4329e7")));

        vendorSpecificAttributes.add(new RadiusPacket.VendorSpecificAttribute().type((byte) 60).length((byte) 35)
                .value(stringToBytes("3235352e3235352e3235352e3235352030303a31313a30313a30303a30303a3031")));

        vendorSpecificAttributes.add(new RadiusPacket.VendorSpecificAttribute().type((byte) 26).length((byte) 6)
                .value(stringToBytes("00002000")));

        vendorSpecificAttributes.add(new RadiusPacket.VendorSpecificAttribute().type((byte) 254).length((byte) 11)
                .value(stringToBytes("487561776569204e45")));

        vendorSpecificAttributes.add(new RadiusPacket.VendorSpecificAttribute().type((byte) 255).length((byte) 4)
                .value(stringToBytes("4e45")));

        vendorSpecificAttributes.add(new RadiusPacket.VendorSpecificAttribute().type((byte) 138).length((byte) 18)
                .value(stringToBytes("696e7465726e65742e6b706e2e636f6d")));

        attributeValuePairs.add(new RadiusPacket.AttributeValuePair().type((byte) 26).length((byte) 86)
                .vendorSpecificAttributes(vendorSpecificAttributes));

        final RadiusPacket expected = new RadiusPacket().code(RadiusPacket.Code.ACCESS_REQUEST).identifier((byte) 87)
                .length((char) 260).authenticator(stringToBytes("2ae0841c195193c2cb32eea3cdced9d7"))
                .attributeValuePairs(attributeValuePairs);

        final RadiusPacket actual = RadiusPacket.parse(stringToBytes(header + payload));
        Assert.assertEquals(actual, expected);
    }

    // Negative test cases

    @Test(expectedExceptions = ParseException.class, expectedExceptionsMessageRegExp = "invalid code")
    public void testParseCodeFails() throws Exception {
        final String header = "105701042ae0841c195193c2cb32eea3cdced9d7";
        final String payload = "010e73696e676c652d737461636b0212ff850dcb9b84559ce5d5e92c983e98fe05060600b0650406ac110" +
                "1010606000000020706000000011f1330303a31313a30313a30303a30303a3031200658382d323d060000000f571758382d3" +
                "22065746820302f362f302f31313a3130312c2058382d3230363031313031303130303030303932623639323030323030304" +
                "d0c313030303030303030301a56000007db3b065b4329e73c233235352e3235352e3235352e3235352030303a31313a30313" +
                "a30303a30303a30311a0600002000fe0b487561776569204e45ff044e458a12696e7465726e65742e6b706e2e636f6d";

        RadiusPacket.parse(stringToBytes(header + payload));
    }
}