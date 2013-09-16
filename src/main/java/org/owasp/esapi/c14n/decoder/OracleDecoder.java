package org.owasp.esapi.c14n.decoder;

import org.owasp.esapi.c14n.codecs.PushbackString;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/16/13
 * Time: 11:03 PM
 * To change this template use File | Settings | File Templates.
 */
public class OracleDecoder implements Decoder {

    /**
     * {@inheritDoc}
     *
     * Returns the decoded version of the character starting at index, or
     * null if no decoding is possible.
     *
     * Formats all are legal
     *   '' decodes to '
     */
    public Character decodeCharacter( PushbackString input ) {
        input.mark();
        Character first = input.next();
        if ( first == null ) {
            input.reset();
            return null;
        }

        // if this is not an encoded character, return null
        if ( first.charValue() != '\'' ) {
            input.reset();
            return null;
        }

        Character second = input.next();
        if ( second == null ) {
            input.reset();
            return null;
        }

        // if this is not an encoded character, return null
        if ( second.charValue() != '\'' ) {
            input.reset();
            return null;
        }
        return( Character.valueOf( '\'' ) );
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
