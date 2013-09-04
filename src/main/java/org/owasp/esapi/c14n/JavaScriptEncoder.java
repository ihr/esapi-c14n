/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.c14n;

import org.owasp.esapi.c14n.util.HexadecimalConverter;
import org.owasp.esapi.c14n.util.StringUtilityMethods;

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
public class JavaScriptEncoder implements Encoder {

    /**
     * Character sets that define characters (in addition to alphanumerics) that are
     * immune from encoding in various formats
     */
    private final static char[] IMMUNE_JAVASCRIPT = {',', '.', '_'};


    /**
     * {@inheritDoc}
     */
    public String encodeForJavaScript(String input) {
        if (input == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            sb.append(encodeCharacter(IMMUNE_JAVASCRIPT, c));
        }
        return sb.toString();
    }

    /**
     * {@inheritDoc}
     * <p/>
     * Returns backslash encoded numeric format. Does not use backslash character escapes
     * such as, \" or \' as these may cause parsing problems. For example, if a javascript
     * attribute, such as onmouseover, contains a \" that will close the entire attribute and
     * allow an attacker to inject another script attribute.
     *
     * @param immune
     */
    public String encodeCharacter(char[] immune, Character c) {

        // check for immune characters
        if (StringUtilityMethods.containsCharacter(c, immune)) {
            return "" + c;
        }

        // check for alphanumeric characters
        String hex = HexadecimalConverter.getHexForNonAlphanumeric(c);
        if (hex == null) {
            return "" + c;
        }

        // Do not use these shortcuts as they can be used to break out of a context
        // if ( ch == 0x00 ) return "\\0";
        // if ( ch == 0x08 ) return "\\b";
        // if ( ch == 0x09 ) return "\\t";
        // if ( ch == 0x0a ) return "\\n";
        // if ( ch == 0x0b ) return "\\v";
        // if ( ch == 0x0c ) return "\\f";
        // if ( ch == 0x0d ) return "\\r";
        // if ( ch == 0x22 ) return "\\\"";
        // if ( ch == 0x27 ) return "\\'";
        // if ( ch == 0x5c ) return "\\\\";

        // encode up to 256 with \\xHH
        String temp = Integer.toHexString(c);
        if (c < 256) {
            String pad = "00".substring(temp.length());
            return "\\x" + pad + temp.toUpperCase();
        }

        // otherwise encode with \\uHHHH
        String pad = "0000".substring(temp.length());
        return "\\u" + pad + temp.toUpperCase();
    }


}
