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
package org.owasp.esapi.c14n.codecs;


/**
 * The pushback string is used by Codecs to allow them to push decoded characters back onto a string
 * for further decoding. This is necessary to detect double-encoding.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public class PushbackString {

    private String input;
    private Character pushback;
    private Character temp;
    private int index = 0;
    private int mark = 0;


    public PushbackString(String input) {
        this.input = input;
    }

    public void pushback(Character c) {
        pushback = c;
    }

    public int index() {
        return index;
    }

    public boolean hasNext() {
        if (pushback != null) return true;
        if (input == null) return false;
        if (input.length() == 0) return false;
        if (index >= input.length()) return false;
        return true;
    }

    public Character next() {
        if (pushback != null) {
            Character save = pushback;
            pushback = null;
            return save;
        }
        if (input == null) return null;
        if (input.length() == 0) return null;
        if (index >= input.length()) return null;
        return Character.valueOf(input.charAt(index++));
    }

    public Character nextHex() {
        Character c = next();
        if (c == null) return null;
        if (isHexDigit(c)) return c;
        return null;
    }

    public Character nextOctal() {
        Character c = next();
        if (c == null) return null;
        if (isOctalDigit(c)) return c;
        return null;
    }

    public static boolean isHexDigit(Character c) {
        if (c == null) return false;
        char ch = c.charValue();
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    }

    public static boolean isOctalDigit(Character c) {
        if (c == null) return false;
        char ch = c.charValue();
        return ch >= '0' && ch <= '7';
    }

    public Character peek() {
        if (pushback != null) return pushback;
        if (input == null) return null;
        if (input.length() == 0) return null;
        if (index >= input.length()) return null;
        return Character.valueOf(input.charAt(index));
    }

    public boolean peek(char c) {
        if (pushback != null && pushback.charValue() == c) return true;
        if (input == null) return false;
        if (input.length() == 0) return false;
        if (index >= input.length()) return false;
        return input.charAt(index) == c;
    }

    public void mark() {
        temp = pushback;
        mark = index;
    }

    public void reset() {
        pushback = temp;
        index = mark;
    }

    public String remainder() {
        String output = input.substring(index);
        if (pushback != null) {
            output = pushback + output;
        }
        return output;
    }
}