package org.owasp.esapi.c14n;


import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.runners.Parameterized.Parameters;
import static org.owasp.esapi.c14n.CanonicalizatorsEnum.*;

@RunWith(Parameterized.class)
public class TestCanonicalizatorsChain {

    private CanonicalizatorsChain canonicalizatorsChain = new CanonicalizatorsChain(JAVASCRIPT.getCanonicalizator(),
            HTML.getCanonicalizator(), PERCENT.getCanonicalizator());

    @Parameters(name = "{index}: canonicalize({0})={1}")
    public static Iterable<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {"%3Cscript&#x3E;alert%28%22hello&#34%29%3B%3C%2Fscript%3E", "<script>alert(\"hello\");</script>"}
        });
    }

    private final String target;
    private final String expectedCanonicalizedString;

    public TestCanonicalizatorsChain(String target, String expectedCanonicalizedString) {
        this.target = target;
        this.expectedCanonicalizedString = expectedCanonicalizedString;
    }

    @Test
    public void shouldPerformCanonicalization() {
        //GIVEN

        //WHEN
        String canonicalizedString = canonicalizatorsChain.canonicalize(target);

        //THEN
        assertThat(canonicalizedString).isEqualTo(expectedCanonicalizedString);
    }
}
