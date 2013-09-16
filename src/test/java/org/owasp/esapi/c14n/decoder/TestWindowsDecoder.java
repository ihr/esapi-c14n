package org.owasp.esapi.c14n.decoder;

import org.junit.Test;
import org.owasp.esapi.c14n.codecs.PushbackString;

import static java.lang.Character.valueOf;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/16/13
 * Time: 11:21 PM
 * To change this template use File | Settings | File Templates.
 */
public class TestWindowsDecoder {

    private WindowsDecoder windowsDecoder = new WindowsDecoder();

    @Test
    public void testWindowsDecode() {
        assertThat("<").isEqualTo(windowsDecoder.decode("^<"));
    }

    @Test
    public void testWindowsDecodeCharCarrotLessThan() {
        assertThat(valueOf('<')).isEqualTo(windowsDecoder.decodeCharacter(new PushbackString("^<")));
    }

}
