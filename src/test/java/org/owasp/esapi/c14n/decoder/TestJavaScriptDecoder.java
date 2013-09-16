package org.owasp.esapi.c14n.decoder;

import org.junit.Test;
import org.owasp.esapi.c14n.codecs.PushbackString;

import static org.assertj.core.api.Assertions.assertThat;

public class TestJavaScriptDecoder {

    private JavaScriptDecoder javaScriptDecoder = new JavaScriptDecoder();

    @Test
    public void shouldDecodeLessSymbolString() {
        //GIVEN
        String input = "\\x3c";

        //WHEN
        String decodedString = javaScriptDecoder.decode(input);

        //THEN
        assertThat(decodedString).isEqualTo("<");
    }

    @Test
    public void shouldDecodeLessSymbolCharacter() {
        //GIVEN
        String input = "\\x3c";

        //WHEN
        Character decodedCharacter = javaScriptDecoder.decodeCharacter(new PushbackString(input));

        //THEN
        assertThat(decodedCharacter).isEqualTo(Character.valueOf('<'));
    }

}
