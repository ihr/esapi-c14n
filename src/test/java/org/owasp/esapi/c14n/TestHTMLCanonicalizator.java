package org.owasp.esapi.c14n;


import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.owasp.esapi.c14n.CanonicalizatorsEnum;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class TestHTMLCanonicalizator {

    private Canonicalizator htmlCanonicalizator = CanonicalizatorsEnum.HTML.getCanonicalizator();

    @Parameters(name = "{index}: canonicalize({0})={1}")
    public static Iterable<Object[]> data() {
        return Arrays.asList(new Object[][]{
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
                {"&#X3C;", "<"},
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
                {"&LT;", "<"}
        });
    }

    private final String target;
    private final String expectedCanonicalizedString;

    public TestHTMLCanonicalizator(String target, String expectedCanonicalizedString) {
        this.target = target;
        this.expectedCanonicalizedString = expectedCanonicalizedString;
    }

    @Test
    public void shouldPerformCanonicalization() {
        //GIVEN

        //WHEN
        String canonicalizedString = htmlCanonicalizator.canonicalize(target);

        //THEN
        assertThat(canonicalizedString).isEqualTo(expectedCanonicalizedString);
    }
}
