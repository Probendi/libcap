package com.probendi.libcap;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class PacketTypeTest {

    @Test
    public void testParseBytes() {
        Assert.assertEquals(PacketType.parse((byte) 0x86, (byte) 0xdd), PacketType.IPv6);
    }

    @Test(dataProvider = "dp")
    public void testParseChar(final char c, final PacketType expected) {
        Assert.assertEquals(PacketType.parse(c), expected);
    }

    // Data providers
    @NotNull
    @Contract(pure = true)
    @DataProvider(name = "dp")
    public static Object[][] dataProvider() {
        int i = 0;
        final Object[][] objects = new Object[PacketType.values().length + 1][2];
        for (final PacketType packetType : PacketType.values()) {
            objects[i][0] = packetType.getType();
            objects[i++][1] = packetType;
        }
        objects[i][0] = (char) 0xffff;
        objects[i][1] = PacketType.UNSUPPORTED;
        return objects;
    }
}