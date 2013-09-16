package org.owasp.esapi.c14n.encoder;

/**
 * Created with IntelliJ IDEA.
 * User: ihristov
 * Date: 9/16/13
 * Time: 9:06 PM
 * To change this template use File | Settings | File Templates.
 */
public abstract class Encoder {

    /**
     * Encode a String so that it can be safely used in a specific context.
     *
     * @param immune
     * @param input
     * 		the String to encode
     * @return the encoded String
     */
    public String encode(char[] immune, String input) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            sb.append(encodeCharacter(immune, c));
        }
        return sb.toString();
    }

    /**
     * Default implementation that should be overridden in specific codecs.
     *
     * @param immune
     * @param c
     * 		the Character to encode
     * @return
     * 		the encoded Character
     */
    public abstract String encodeCharacter( char[] immune, Character c );

}
