/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP) Enterprise Security API
 * (ESAPI) project. For details, please see <a
 * href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 * 
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the LICENSE
 * before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.c14n.encoder;

import static org.owasp.esapi.c14n.util.HexadecimalConverter.getHexForNonAlphanumeric;
import static org.owasp.esapi.c14n.util.StringUtilityMethods.containsCharacter;

/**
 * Implementation of the Codec interface for backslash encoding used in CSS.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class CSSEncoder extends Encoder
{
    /**
	 * {@inheritDoc}
	 *
     * Returns backslash encoded character.
     *
     * @param immune
     */
    public String encodeCharacter(char[] immune, Character c) {
		// check for immune characters
		if (containsCharacter(c, immune) ) {
			return ""+c;
		}
		
		// check for alphanumeric characters
		String hex = getHexForNonAlphanumeric(c);
		if ( hex == null ) {
			return ""+c;
		}
		
		// return the hex and end in whitespace to terminate
        return "\\" + hex + " ";
    }

    


}
