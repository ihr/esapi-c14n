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
package org.owasp.esapi.c14n.decoder;

import org.owasp.esapi.c14n.codecs.PushbackString;

import static org.owasp.esapi.c14n.util.HtmlEntityMap.getNamedEntity;

/**
 * Implementation of the Codec interface for HTML entity encoding.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public class HtmlEntityDecoder implements Decoder {

    /**
     *
     */
    public HtmlEntityDecoder() {
    }

    /**
     * {@inheritDoc}
     * <p/>
     * Returns the decoded version of the character starting at index, or
     * null if no decoding is possible.
     * <p/>
     * Formats all are legal both with and without semi-colon, upper/lower case:
     * &#dddd;
     * &#xhhhh;
     * &name;
     */
    public Character decodeCharacter(PushbackString input) {
        input.mark();
        Character first = input.next();
        if (first == null) {
            input.reset();
            return null;
        }

        // if this is not an encoded character, return null
        if (first != '&') {
            input.reset();
            return null;
        }

        // test for numeric encodings
        Character second = input.next();
        if (second == null) {
            input.reset();
            return null;
        }

        if (second == '#') {
            // handle numbers
            Character c = getNumericEntity(input);
            if (c != null) return c;
        } else if (Character.isLetter(second.charValue())) {
            // handle entities
            input.pushback(second);

            Character c = getNamedEntity(input);
            if (c != null) return c;
        }
        input.reset();
        return null;
    }

    /**
     * getNumericEntry checks input to see if it is a numeric entity
     *
     * @param input The input to test for being a numeric entity
     * @return null if input is null, the character of input after decoding
     */
    private Character getNumericEntity(PushbackString input) {
        Character first = input.peek();
        if (first == null) return null;

        if (first == 'x' || first == 'X') {
            input.next();
            return parseHex(input);
        }
        return parseNumber(input);
    }

    /**
     * Parse a decimal number, such as those from JavaScript's String.fromCharCode(value)
     *
     * @param input decimal encoded string, such as 65
     * @return character representation of this decimal value, e.g. A
     * @throws NumberFormatException
     */
    private Character parseNumber(PushbackString input) {
        StringBuilder sb = new StringBuilder();
        while (input.hasNext()) {
            Character c = input.peek();

            // if character is a digit then add it on and keep going
            if (Character.isDigit(c.charValue())) {
                sb.append(c);
                input.next();

                // if character is a semi-colon, eat it and quit
            } else if (c == ';') {
                input.next();
                break;

                // otherwise just quit
            } else {
                break;
            }
        }
        try {
            int i = Integer.parseInt(sb.toString());
            if (Character.isValidCodePoint(i)) {
                return (char) i;
            }
        } catch (NumberFormatException e) {
            // throw an exception for malformed entity?
        }
        return null;
    }

    /**
     * Parse a hex encoded entity
     *
     * @param input Hex encoded input (such as 437ae;)
     * @return A single character from the string
     * @throws NumberFormatException
     */
    private Character parseHex(PushbackString input) {
        StringBuilder sb = new StringBuilder();
        while (input.hasNext()) {
            Character c = input.peek();

            // if character is a hex digit then add it on and keep going
            if ("0123456789ABCDEFabcdef".indexOf(c) != -1) {
                sb.append(c);
                input.next();

                // if character is a semi-colon, eat it and quit
            } else if (c == ';') {
                input.next();
                break;

                // otherwise just quit
            } else {
                break;
            }
        }
        try {
            int i = Integer.parseInt(sb.toString(), 16);
            if (Character.isValidCodePoint(i)) {
                return (char) i;
            }
        } catch (NumberFormatException e) {
            // throw an exception for malformed entity?
        }
        return null;
    }


    public String decode(String input) {
        StringBuilder sb = new StringBuilder();
        PushbackString pbs = new PushbackString(input);
        while (pbs.hasNext()) {
            Character c = decodeCharacter(pbs);
            if (c != null) {
                sb.append(c);
            } else {
                sb.append(pbs.next());
            }
        }
        return sb.toString();
    }
}
