package org.owasp.esapi.c14n;

import java.util.Arrays;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/4/13
 * Time: 1:48 PM
 * To change this template use File | Settings | File Templates.
 */
public class CanonicalizatorsChain implements Canonicalizator {

    private final List<Canonicalizator> canonicalizators;

    public CanonicalizatorsChain(Canonicalizator... canonicalizators) {
        this.canonicalizators = Arrays.asList(canonicalizators);
    }


    public String canonicalize(String input) {
        String result = input;
        for (Canonicalizator canonicalizator : canonicalizators) {
            result = canonicalizator.canonicalize(result);
        }
        return result;
    }

    public String canonicalize(String input, boolean restrictMultiple, boolean restrictMixed) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
