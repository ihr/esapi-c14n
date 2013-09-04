package org.owasp.esapi.c14n;


import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.owasp.esapi.c14n.CanonicalizatorsEnum;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class TestJavaScriptCanonicalizator {

    private Canonicalizator javaScriptCanonicalizator = CanonicalizatorsEnum.JAVASCRIPT.getCanonicalizator();

    @Parameters(name = "{index}: canonicalize({0})={1}")
    public static Iterable<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {"\\0", "\0"}, // null string
                {"\\b", "\b"}, // backspace
                {"\\t", "\t"}, // tab
                {"\\n", "\n"}, // newline
                {"\\v", "" + (char) 0x0b}, // vertical tab (move down one line, on the same column)
                {"\\f", "\f"}, // form feed/new page (eject page from printer)
                {"\\r", "\r"}, // carriage return
                {"\\'", "\'"},
                {"\\\"", "\""},
                {"\\\\", "\\"},
                {"\\<", "<"},
                {"\\u003c", "<"},
                {"\\U003c", "<"},
                {"\\u003C", "<"},
                {"\\U003C", "<"},
                {"\\x3c", "<"},
                {"\\X3c", "<"},
                {"\\x3C", "<"},
                {"\\X3C", "<"},
                // Test null paths
                {null, null}
                // test exception paths
                /* TODO add HTML de/encoding capabilities to support the following:
                {"%25", "%"},

                {"%25F", "%F"},
                {"%3c", "<"},
                {"%3C", "<"},
                {"%X1", "%X1"},
                {"&lt", "<"},
                {"&LT", "<"},
                {"&lt;", "<"},
                {"&LT;", "<"},
                {"&#37;", "%"},
                {"&#37", "%"},
                {"&#37b", "%b"},
                {"&#x3c", "<",},
                {"&#x3c;", "<"},
                {"&#x3C", "<"},
                {"&#X3c", "<"},
                {"&#X3C", "<"},
                {"&#X3C;",},
                // percent encoding
                {"%3c", "<"},
                {"%3C", "<"},

                // html entity encoding
                {"&#60", "<"},
                {"&#060", "<"},
                {"&#0060", "<"},
                {"&#00060", "<"},
                {"&#000060", "<"},
                {"&#0000060", "<"},
                {"&#60;", "<"},
                {"&#060;", "<"},
                {"&#0060;", "<"},
                {"&#00060;", "<"},
                {"&#000060;", "<"},
                {"&#0000060;", "<"},
                {"&#x3c", "<"},
                {"&#x03c", "<"},
                {"&#x003c", "<"},
                {"&#x0003c", "<"},
                {"&#x00003c", "<"},
                {"&#x000003c", "<"},
                {"&#x3c;", "<"},
                {"&#x03c;", "<"},
                {"&#x003c;", "<"},
                {"&#x0003c;", "<"},
                {"&#x00003c;", "<"},
                {"&#x000003c;", "<"},
                {"&#X3c", "<"},
                {"&#X03c", "<"},
                {"&#X003c", "<"},
                {"&#X0003c", "<"},
                {"&#X00003c", "<"},
                {"&#X000003c", "<"},
                {"&#X3c;", "<"},
                {"&#X03c;", "<"},
                {"&#X003c;", "<"},
                {"&#X0003c;", "<"},
                {"&#X00003c;", "<"},
                {"&#X000003c;", "<"},
                {"&#x3C", "<"},
                {"&#x03C", "<"},
                {"&#x003C", "<"},
                {"&#x0003C", "<"},
                {"&#x00003C", "<"},
                {"&#x000003C", "<"},
                {"&#x3C;", "<"},
                {"&#x03C;", "<"},
                {"&#x003C;", "<"},
                {"&#x0003C;", "<"},
                {"&#x00003C;", "<"},
                {"&#x000003C;", "<"},
                {"&#X3C", "<"},
                {"&#X03C", "<"},
                {"&#X003C", "<"},
                {"&#X0003C", "<"},
                {"&#X00003C", "<"},
                {"&#X000003C", "<"},
                {"&#X3C;", "<"},
                {"&#X03C;", "<"},
                {"&#X003C;", "<"},
                {"&#X0003C;", "<"},
                {"&#X00003C;", "<"},
                {"&#X000003C;", "<"},
                {"&lt", "<"},
                {"&lT", "<"},
                {"&Lt", "<"},
                {"&LT", "<"},
                {"&lt;", "<"},
                {"&lT;", "<"},
                {"&Lt;", "<"},
                {"&LT;", "<"},
                {"%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E", "<script>alert(\"hello\");</script>"},
                {"%3Cscript&#x3E;alert%28%22hello&#34%29%3B%3C%2Fscript%3E", "<script>alert(\"hello\");</script>"} */
        });
    }

    private final String target;
    private final String expectedCanonicalizedString;

    public TestJavaScriptCanonicalizator(String target, String expectedCanonicalizedString) {
        this.target = target;
        this.expectedCanonicalizedString = expectedCanonicalizedString;
    }

    @Test
    public void shouldPerformCanonicalization() {
        //GIVEN

        //WHEN
        String canonicalizedString = javaScriptCanonicalizator.canonicalize(target);

        //THEN
        assertThat(canonicalizedString).isEqualTo(expectedCanonicalizedString);
    }
}
