package org.owasp.esapi.c14n.encoder;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/16/13
 * Time: 9:19 PM
 * To change this template use File | Settings | File Templates.
 */
public class TestCssEncoder {

    private static final char[] EMPTY_CHAR_ARRAY = new char[0];

    private CSSEncoder cssEncoder = new CSSEncoder();

    @Test
    public void testCSSEncodeChar() {
        assertThat("\\3c ").isEqualTo(cssEncoder.encodeCharacter(EMPTY_CHAR_ARRAY, Character.valueOf('<')));
    }

    @Test
    public void testCSSEncodeChar0x100() {
        char in = 0x100;
        String inStr = Character.toString(in);
        String expected = "\\100 ";
        String result;

        result = cssEncoder.encodeCharacter(EMPTY_CHAR_ARRAY, in);

        // this should be escaped
        assertThat(inStr).isNotEqualTo(result);
        assertThat(expected).isEqualTo(result);
    }

    @Test
    public void testCSSEncodeStr0x100() {
        char in = 0x100;
        String inStr = Character.toString(in);
        String expected = "\\100 ";
        String result;

        result = cssEncoder.encode(EMPTY_CHAR_ARRAY, inStr);

        // this should be escaped
        assertThat(inStr).isNotEqualTo(result);
        assertThat(expected).isEqualTo(result);
    }

    @Test
    public void testCSSEncode() {
        assertThat("\\3c ").isEqualTo(cssEncoder.encode(EMPTY_CHAR_ARRAY, "<"));
    }

}
