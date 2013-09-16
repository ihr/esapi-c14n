package org.owasp.esapi.c14n.decoder;

import org.junit.Test;
import org.owasp.esapi.c14n.codecs.PushbackString;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/16/13
 * Time: 11:13 PM
 * To change this template use File | Settings | File Templates.
 */
public class TestUnixDecoder {

    private UnixDecoder unixDecoder = new UnixDecoder();

    @Test
    public void testUnixDecode() {
        assertThat("<").isEqualTo(unixDecoder.decode("\\<"));
    }

    @Test
    public void testUnixDecodeCharBackSlashLessThan() {
        assertThat(Character.valueOf('<')).isEqualTo(unixDecoder.decodeCharacter(new PushbackString("\\<")));
    }


}
