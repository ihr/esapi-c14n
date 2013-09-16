package org.owasp.esapi.c14n.decoder;

import org.junit.Test;
import org.owasp.esapi.c14n.codecs.PushbackString;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/16/13
 * Time: 11:04 PM
 * To change this template use File | Settings | File Templates.
 */
public class TestOracleDecoder {

    private OracleDecoder oracleDecoder  = new OracleDecoder();

    @Test
    public void testOracleDecode() {
        assertThat("\'").isEqualTo(oracleDecoder.decode("\'\'"));
    }

    @Test
    public void testOracleDecodeCharBackSlashLessThan() {
        assertThat(Character.valueOf('\'')).isEqualTo(oracleDecoder.decodeCharacter(new PushbackString("\'\'")));
    }

}
