package org.owasp.esapi.c14n.util;

public class StringUtilityMethods {
    /**
     * Utility to search a char[] for a specific char.
     *
     * @param c
     * @param array
     * @return
     */
    public static boolean containsCharacter(char c, char[] array) {
        for (char ch : array) {
            if (c == ch) return true;
        }
        return false;
    }
}
