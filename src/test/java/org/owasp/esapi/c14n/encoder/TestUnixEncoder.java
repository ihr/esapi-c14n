package org.owasp.esapi.c14n.encoder;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/16/13
 * Time: 11:13 PM
 * To change this template use File | Settings | File Templates.
 */
public class TestUnixEncoder {

    private static final char[] EMPTY_CHAR_ARRAY = new char[0];

    private UnixEncoder unixEncoder = new UnixEncoder();

    @Test
    public void testUnixEncode()
    {
        assertThat("\\<").isEqualTo(unixEncoder.encode(EMPTY_CHAR_ARRAY, "<"));
    }

    @Test
    public void testUnixEncodeChar()
    {
        assertThat("\\<").isEqualTo(unixEncoder.encodeCharacter(EMPTY_CHAR_ARRAY, Character.valueOf('<')));
    }

    @Test
    public void testUnixEncodeChar0x100()
    {
        char in = 0x100;
        String inStr = Character.toString(in);
        String expected = "\\" + in;
        String result;

        result = unixEncoder.encodeCharacter(EMPTY_CHAR_ARRAY, in);
        // this should be escaped
        assertThat(inStr).isNotEqualTo(result);
        assertThat(expected).isEqualTo(result);
    }

    @Test
    public void testUnixEncodeStr0x100()
    {
        char in = 0x100;
        String inStr = Character.toString(in);
        String expected = "\\" + in;
        String result;

        result = unixEncoder.encode(EMPTY_CHAR_ARRAY, inStr);
        // this should be escaped
        assertThat(inStr).isNotEqualTo(result);
        assertThat(expected).isEqualTo(result);
    }

}
