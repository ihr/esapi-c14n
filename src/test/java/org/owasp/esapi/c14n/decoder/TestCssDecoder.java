package org.owasp.esapi.c14n.decoder;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/16/13
 * Time: 10:51 PM
 * To change this template use File | Settings | File Templates.
 */
public class TestCssDecoder {

    private final CssDecoder cssDecoder = new CssDecoder();

    @Test
    public void testCSSInvalidCodepointDecode() {
        assertThat("\uFFFDg").isEqualTo(cssDecoder.decode("\\abcdefg"));
    }

    @Test
    public void testCSSDecode() {
        assertThat("<").isEqualTo(cssDecoder.decode("\\<"));
    }

    @Test
    public void testCSSDecodeHexNoSpace() {
        assertThat("Axyz").isEqualTo(cssDecoder.decode("\\41xyz"));
    }

    @Test
    public void testCSSDecodeZeroHexNoSpace() {
        assertThat("Aabc").isEqualTo(cssDecoder.decode("\\000041abc"));
    }

    @Test
    public void testCSSDecodeHexSpace() {
        assertThat("Aabc").isEqualTo(cssDecoder.decode("\\41 abc"));
    }

    @Test
    public void testCSSDecodeNL() {
        assertThat("abcxyz").isEqualTo(cssDecoder.decode("abc\\\nxyz"));
    }

    @Test
    public void testCSSDecodeCRNL() {
        assertThat("abcxyz").isEqualTo(cssDecoder.decode("abc\\\r\nxyz"));
    }

}

