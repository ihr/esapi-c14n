package org.owasp.esapi.c14n.decoder;

import org.owasp.esapi.c14n.codecs.PushbackString;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/16/13
 * Time: 11:12 PM
 * To change this template use File | Settings | File Templates.
 */
public class UnixDecoder implements Decoder {

    /**
     * {@inheritDoc}
     * <p/>
     * Returns the decoded version of the character starting at index, or
     * null if no decoding is possible.
     * <p/>
     * Formats all are legal both upper/lower case:
     * \x - all special characters
     */
    public Character decodeCharacter(PushbackString input) {
        input.mark();
        Character first = input.next();
        if (first == null) {
            input.reset();
            return null;
        }

        // if this is not an encoded character, return null
        if (first.charValue() != '\\') {
            input.reset();
            return null;
        }

        Character second = input.next();
        return second;
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
