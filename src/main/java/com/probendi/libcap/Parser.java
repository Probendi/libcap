package com.probendi.libcap;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import static com.probendi.libcap.Validator.validateObject;

/**
 * A {@code PCAP} parser (see https://wiki.wireshark.org/Development/LibpcapFileFormat)
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class Parser implements Closeable {

    /**
     * The global header's length in octets.
     */
    public static final int HEADER_LENGTH = 32 * 6 / 8;

    private static final String PCAP_HDR = "magic_number: 0x%x\tversion_major: 0x%x\tversion_minor: 0x%x\t" +
            "thiszone: 0x%x\tsigfigs: 0x%x\tsnaplen: %x\tnetwork: 0x%x\t";
    private static final String PCAPREC_HDR = "ts_sec: 0x%x\tts_usec: 0x%x\tinc_len: %x\torig_len: 0x%x";

    protected int magic_number;
    protected char version_major;
    protected char version_minor;
    protected int thiszone;
    protected int sigfigs;
    protected int snaplen;
    protected int network;

    private final Logger logger = Logger.getLogger(this.getClass().getName());
    private final InputStream in;
    // size increased for handling loopback interface of a Unix device
    private final byte[] buffer = new byte[0x10000];

    private int frame = 0;
    private boolean swapped = false;

    /**
     * Formats the given bytes into a long.
     *
     * @param bytes the bytes to be formatted
     * @return a long
     */
    public static long bytesToLong(final byte[] bytes) {
        return Long.parseLong(Parser.bytesToString(bytes).substring(2), 16);
    }

    /**
     * Formats the given bytes into an hex string, e.g. {@code 0x0a2a0001}.
     *
     * @param bytes the bytes to be formatted
     * @return an hex string
     */
    @NotNull
    @Contract("null -> !null")
    public static String bytesToString(final byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        final StringBuilder sb = new StringBuilder("0x");
        for (final byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Reads a char from the given bytes.
     *
     * @param b0 the most significant byte
     * @param b1 the least significant byte
     * @return a char from the given array
     */
    @Contract(pure = true)
    public static char readChar(final byte b0, final byte b1) {
        return ByteBuffer.wrap(new byte[]{b0, b1}).getChar();
    }

    /**
     * Reads an int from the given bytes.
     *
     * @param b0 the most significant byte
     * @param b1 the second most significant byte
     * @param b2 the third most significant byte
     * @param b3 the least significant byte
     * @return an int from the given array
     */
    @Contract(pure = true)
    public static int readInt(final byte b0, final byte b1, final byte b2, final byte b3) {
        return ByteBuffer.wrap(new byte[]{b0, b1, b2, b3}).getInt();
    }


    /**
     * Return a {@link String} object from the given {@code null-terminated} string.
     *
     * @param bytes the null-terminated string as a byte array
     * @return a {@link String} object from the given {@code null-terminated} string
     */
    public static String readNullTerminatedString(final byte[] bytes) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : bytes) {
            if (b == (byte) 0) break;
            sb.append((char) b);
        }
        return sb.toString();
    }

    /**
     * Creates a new {@code Parser} object for the given file.
     *
     * @param file the file to be parsed
     * @throws IllegalArgumentException if {@code file} is not set
     * @throws IOException              if the file could not be read
     */
    public Parser(final Path file) throws IOException {
        validateObject("file", file);
        in = new BufferedInputStream(new FileInputStream(file.toFile()));
        readGlobalHeader();
    }

    /**
     * Creates a new {@code Parser} object for the given array.
     *
     * @param bytes the bytes to be parsed
     * @throws IllegalArgumentException if {@code bytes} is not set
     * @throws IOException              if the global header could not be read
     */
    protected Parser(final byte[] bytes) throws IOException {
        validateObject("bytes", bytes);
        in = new BufferedInputStream(new ByteArrayInputStream(bytes));
        readGlobalHeader();
    }

    @Override
    public void close() {
        try {
            in.close();
        } catch (final IOException e) {
            logger.log(Level.WARNING, "I/O error while closing this parser", e);
        }
    }

    /**
     * Reads the next record.
     *
     * @return the next record or {@code null} if there are no more records
     * @throws IOException if the file could not be read
     */
    public Record readRecord() throws IOException {
        final int ts_sec = readInt(); // guint32
        final int ts_usec = readInt(); // guint32
        final int incl_len = readInt(); // guint32
        final int orig_len = readInt(); // guint32
        logger.finest(String.format(PCAPREC_HDR, ts_sec, ts_usec, incl_len, orig_len));

        if (incl_len == -1) {
            return null;
        }
        final int n = in.read(buffer, 0, incl_len);
        final byte[] bytes = Arrays.copyOfRange(buffer, 0, n);
        // the last packet may have been truncated
        if (incl_len != bytes.length) {
            return null;
        }
        return new Record().frame(++frame).ts_sec(ts_sec).ts_usec(ts_usec).incl_len(incl_len).orig_len(orig_len).bytes(bytes);
    }

    /**
     * Reads the global header.
     *
     * @throws IOException if the file could not be read
     */
    protected void readGlobalHeader() throws IOException {
        magic_number = readInt(); // guint32
        swapped = magic_number == 0xd4c3b2a1;
        version_major = readShort(); // guint16
        version_minor = readShort(); // guint16
        thiszone = readInt(); // gint32
        sigfigs = readInt(); // guint32
        snaplen = readInt(); // guint32
        network = readInt(); // guint32
    }

    /**
     * Reads an unsigned integer which is casted into a long.
     *
     * @return an unsigned integer which is casted into a long
     * @throws IOException if the file could not be read
     */
    private int readInt() throws IOException {
        final byte b0 = (byte) in.read();
        final byte b1 = (byte) in.read();
        final byte b2 = (byte) in.read();
        final byte b3 = (byte) in.read();
        final byte[] bytes = swapped ? new byte[]{b3, b2, b1, b0} : new byte[]{b0, b1, b2, b3};
        return ByteBuffer.wrap(bytes).getInt();
    }

    /**
     * Reads an unsigned short which is casted into an integer.
     *
     * @return an unsigned short which is casted into an integer
     * @throws IOException if the file could not be read
     */
    private char readShort() throws IOException {
        final byte b0 = (byte) in.read();
        final byte b1 = (byte) in.read();
        final byte[] bytes = swapped ? new byte[]{b1, b0} : new byte[]{b0, b1};
        return ByteBuffer.wrap(bytes).getChar();
    }
}
