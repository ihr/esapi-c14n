package org.owasp.esapi.c14n;

import org.owasp.esapi.c14n.decoder.HtmlEntityDecoder;
import org.owasp.esapi.c14n.decoder.JavaScriptDecoder;
import org.owasp.esapi.c14n.decoder.PercentDecoder;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/4/13
 * Time: 1:55 PM
 * To change this template use File | Settings | File Templates.
 */
public enum CanonicalizatorsEnum {
    JAVASCRIPT(new JavaScriptCanonicalizator(new JavaScriptDecoder())), HTML(new HTMLCanonicalizator(new HtmlEntityDecoder())),
    PERCENT(new PercentCanonicalizator(new PercentDecoder()));

    private final Canonicalizator canonicalizator;

    CanonicalizatorsEnum(Canonicalizator canonicalizator) {
        this.canonicalizator = canonicalizator;
    }


    public Canonicalizator getCanonicalizator() {
        return canonicalizator;
    }
}
