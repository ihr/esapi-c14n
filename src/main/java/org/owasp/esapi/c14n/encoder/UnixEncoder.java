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
package org.owasp.esapi.c14n.encoder;


import org.owasp.esapi.c14n.codecs.Codec;
import org.owasp.esapi.c14n.util.HexadecimalConverter;
import org.owasp.esapi.c14n.util.StringUtilityMethods;

/**
 * Implementation of the Codec interface for '\' encoding from Unix command shell.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class UnixEncoder extends Encoder {

	/**
	 * {@inheritDoc}
	 * 
	 * Returns backslash-encoded character
     *
     * @param immune
     */
	public String encodeCharacter( char[] immune, Character c ) {
		char ch = c.charValue();
		
		// check for immune characters
		if (StringUtilityMethods.containsCharacter( ch, immune ) ) {
			return ""+ch;
		}
		
		// check for alphanumeric characters
		String hex = HexadecimalConverter.getHexForNonAlphanumeric(ch);
		if ( hex == null ) {
			return ""+ch;
		}
		
        return "\\" + c;
	}
	
	

}