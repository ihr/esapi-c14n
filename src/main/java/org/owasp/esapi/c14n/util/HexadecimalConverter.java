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
package org.owasp.esapi.c14n.util;

public class HexadecimalConverter {

    /**
     * Initialize an array to mark which characters are to be encoded. Store the hex
     * string for that character to save time later. If the character shouldn't be
     * encoded, then store null.
     */
    private static final String[] hex = new String[256];

    static {
        for (char c = 0; c < 0xFF; c++) {
            if (c >= 0x30 && c <= 0x39 || c >= 0x41 && c <= 0x5A || c >= 0x61 && c <= 0x7A) {
                hex[c] = null;
            } else {
                hex[c] = toHex(c).intern();
            }
        }
    }

    /**
     * Lookup the hex value of any character that is not alphanumeric.
     *
     * @param c The character to lookup.
     * @return null if alphanumeric or the character code in hex.
     */
    public static String getHexForNonAlphanumeric(char c) {
        if (c < 0xFF)
            return hex[c];
        return toHex(c);
    }

    public static String toHex(char c) {
        return Integer.toHexString(c);
    }

}
