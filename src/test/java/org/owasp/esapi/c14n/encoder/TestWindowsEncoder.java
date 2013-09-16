package org.owasp.esapi.c14n.encoder;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/16/13
 * Time: 11:23 PM
 * To change this template use File | Settings | File Templates.
 */
public class TestWindowsEncoder {

    private static final char[] EMPTY_CHAR_ARRAY = new char[0];

    private WindowsEncoder windowsEncoder = new WindowsEncoder();

    @Test
    public void testWindowsEncode() {
        assertThat("^<").isEqualTo(windowsEncoder.encode(EMPTY_CHAR_ARRAY, "<"));
    }

    @Test
    public void testWindowsEncodeChar() {
        assertThat("^<").isEqualTo(windowsEncoder.encodeCharacter(EMPTY_CHAR_ARRAY, Character.valueOf('<')));
    }

    @Test
    public void testWindowsEncodeChar0x100() {
        char in = 0x100;
        String inStr = Character.toString(in);
        String expected = "^" + in;
        String result;

        result = windowsEncoder.encodeCharacter(EMPTY_CHAR_ARRAY, in);
        // this should be escaped
        assertThat(inStr).isNotEqualTo(result);
        assertThat(expected).isEqualTo(result);
    }

    @Test
    public void testWindowsEncodeStr0x100() {
        char in = 0x100;
        String inStr = Character.toString(in);
        String expected = "^" + in;
        String result;

        result = windowsEncoder.encode(EMPTY_CHAR_ARRAY, inStr);
        // this should be escaped
        assertThat(inStr).isNotEqualTo(result);
        assertThat(expected).isEqualTo(result);
    }
}
