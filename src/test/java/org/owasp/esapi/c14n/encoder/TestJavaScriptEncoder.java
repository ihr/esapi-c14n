package org.owasp.esapi.c14n.encoder;

import org.junit.Test;
import org.owasp.esapi.c14n.JavaScriptEncoder;

import static org.assertj.core.api.Assertions.assertThat;

public class TestJavaScriptEncoder {

    private static final char[] EMPTY_CHAR_ARRAY = new char[0];

    private JavaScriptEncoder javaScriptEncoder = new JavaScriptEncoder();

    @Test
    public void shouldEncodeLessThenSymbolString() {
        //GIVEN
        String input = "<";

        //WHEN
        String encodedString = javaScriptEncoder.encodeForJavaScript(input);

        //THEN
        assertThat(encodedString).isEqualTo("\\x3C");
    }

    @Test
    public void shouldEncodeLessThenSymbolCharacter() {
        //GIVEN
        Character lessThenSymbolCharacter = Character.valueOf('<');

        //WHEN
        String encodedString = javaScriptEncoder.encodeCharacter(EMPTY_CHAR_ARRAY, lessThenSymbolCharacter);

        //THEN
        assertThat(encodedString).isEqualTo("\\x3C");
    }

    @Test
    public void shouldEncodeAtCharacterSymbol() {
        //GIVEN
        char in = 0x100; //@

        //WHEN
        String result = javaScriptEncoder.encodeCharacter(EMPTY_CHAR_ARRAY, in);

        //THEN
        assertThat(Character.toString(in)).isNotEqualTo(result);
        assertThat("\\u0100").isEqualTo(result);
    }

    @Test
    public void shouldEncodeAtStringSymbol() {
        //GIVEN
        char in = 0x100;
        String inStr = Character.toString(in);

        //WHEN
        String result = javaScriptEncoder.encodeForJavaScript(inStr);

        //THEN
        assertThat(inStr).isNotEqualTo(result);
        assertThat("\\u0100").isEqualTo(result);
    }

}
