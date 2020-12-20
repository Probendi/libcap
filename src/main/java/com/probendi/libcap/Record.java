package com.probendi.libcap;

import java.util.Arrays;

/**
 * A {@code PCAP} record.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class Record {

    /**
     * The header's length in octets.
     */
    public static final int HEADER_LENGTH = 4 * 32 / 8;

    private int frame;
    private int ts_sec;
    private int ts_usec;
    private int incl_len;
    private int orig_len;
    private byte[] bytes;

    public Record() {
    }

    public int getFrame() {
        return frame;
    }

    public Record frame(final int frame) {
        this.frame = frame;
        return this;
    }

    public long getTs_sec() {
        return ts_sec;
    }

    public Record ts_sec(final int ts_sec) {
        this.ts_sec = ts_sec;
        return this;
    }

    public long getTs_usec() {
        return ts_usec;
    }

    public Record ts_usec(final int ts_usec) {
        this.ts_usec = ts_usec;
        return this;
    }

    public long getIncl_len() {
        return incl_len;
    }

    public Record incl_len(final int incl_len) {
        this.incl_len = incl_len;
        return this;
    }

    public long getOrig_len() {
        return orig_len;
    }

    public Record orig_len(final int orig_len) {
        this.orig_len = orig_len;
        return this;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public Record bytes(final byte[] bytes) {
        this.bytes = bytes;
        return this;
    }

    public String getDestination() {
        return Parser.bytesToString(Arrays.copyOfRange(bytes, 0, 6));
    }

    public String getSource() {
        return Parser.bytesToString(Arrays.copyOfRange(bytes, 6, 12));
    }

    /**
     * Returns the Ethernet type of this record.
     *
     * @return the Ethernet type of this record
     */
    public PacketType getType() {
        return PacketType.parse(bytes[0xc], bytes[0xd]);
    }
}
