package org.owasp.esapi.c14n.encoder;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/16/13
 * Time: 11:08 PM
 * To change this template use File | Settings | File Templates.
 */
public class TestOracleEncoder {

    private static final char[] EMPTY_CHAR_ARRAY = new char[0];

    private OracleEncoder oracleEncoder = new OracleEncoder();

    @Test
    public void testOracleEncode() {
        assertThat("\'\'").isEqualTo(oracleEncoder.encode(EMPTY_CHAR_ARRAY, "\'"));
    }

    @Test
    public void testOracleEncodeChar() {
        assertThat("\'\'").isEqualTo(oracleEncoder.encodeCharacter(EMPTY_CHAR_ARRAY, Character.valueOf('\'')));
    }

}
