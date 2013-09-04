package org.owasp.esapi.c14n;


import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.owasp.esapi.c14n.CanonicalizatorsEnum;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class TestPercentCanonicalizator {

    private Canonicalizator percentCanonicalizator = CanonicalizatorsEnum.PERCENT.getCanonicalizator();

    @Parameters(name = "{index}: canonicalize({0})={1}")
    public static Iterable<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {"%25", "%"},
                {"%25F", "%F"},
                {"%3c", "<"},
                {"%3C", "<"},
                {"%X1", "%X1"},
                {"%3c", "<"},
                {"%3C", "<"},
                {"%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E", "<script>alert(\"hello\");</script>"}
        });
    }

    private final String target;
    private final String expectedCanonicalizedString;

    public TestPercentCanonicalizator(String target, String expectedCanonicalizedString) {
        this.target = target;
        this.expectedCanonicalizedString = expectedCanonicalizedString;
    }

    @Test
    public void shouldPerformCanonicalization() {
        //GIVEN

        //WHEN
        String canonicalizedString = percentCanonicalizator.canonicalize(target);

        //THEN
        assertThat(canonicalizedString).isEqualTo(expectedCanonicalizedString);
    }
}
