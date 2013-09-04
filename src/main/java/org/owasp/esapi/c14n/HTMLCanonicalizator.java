/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This code within this file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Ivan Hristov <a href="http://ingini.org">ingini.org</a>
 * @created 2007
 */
package org.owasp.esapi.c14n;


import org.owasp.esapi.c14n.decoder.HTMLEntityDecoder;

/**
 * Reference implementation of the Encoder interface. This implementation takes
 * a whitelist approach to encoding, meaning that everything not specifically identified in a
 * list of "immune" characters is encoded.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @see Encoder
 * @since June 1, 2007
 */
public class HTMLCanonicalizator implements Canonicalizator {

    private final HTMLEntityDecoder htmlEntityDecoder;

    public HTMLCanonicalizator(HTMLEntityDecoder htmlEntityDecoder) {
        this.htmlEntityDecoder = htmlEntityDecoder;
    }

    /**
     * {@inheritDoc}
     */
    public String canonicalize(String input) {
        if (input == null) {
            return null;
        }

        String working = input;
        boolean clean = false;
        while (!clean) {
            clean = true;

                String old = working;
                working = htmlEntityDecoder.decode(working);
                if (!old.equals(working)) {
                    clean = false;
                }
        }
        return working;
    }

    public String canonicalize(String input, boolean restrictMultiple, boolean restrictMixed) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
