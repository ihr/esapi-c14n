package org.owasp.esapi.c14n.encoder;

import org.owasp.esapi.c14n.util.HexadecimalConverter;
import org.owasp.esapi.c14n.util.HtmlEntityMap;
import org.owasp.esapi.c14n.util.StringUtilityMethods;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/16/13
 * Time: 9:11 PM
 * To change this template use File | Settings | File Templates.
 */
public class HtmlEntityEncoder extends Encoder {
    private static final char REPLACEMENT_CHAR = '\ufffd';
    private static final String REPLACEMENT_HEX = "fffd";
    private static final String REPLACEMENT_STR = "" + REPLACEMENT_CHAR;

    /**
     * {@inheritDoc}
     * <p/>
     * Encodes a Character for safe use in an HTML entity field.
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

        // check for illegal characters
        if ((c <= 0x1f && c != '\t' && c != '\n' && c != '\r') || (c >= 0x7f && c <= 0x9f)) {
            hex = REPLACEMENT_HEX;    // Let's entity encode this instead of returning it
            c = REPLACEMENT_CHAR;
        }

        // check if there's a defined entity
        String entityName = (String) HtmlEntityMap.characterToEntityMap.get(c);
        if (entityName != null) {
            return "&" + entityName + ";";
        }

        // return the hex entity as suggested in the spec
        return "&#x" + hex + ";";
    }

}
