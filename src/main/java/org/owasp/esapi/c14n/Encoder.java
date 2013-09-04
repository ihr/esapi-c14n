package org.owasp.esapi.c14n;

/**
 * The Encoder interface contains a number of methods for decoding input and encoding output
 * so that it will be safe for a variety of interpreters. To prevent
 * double-encoding, callers should make sure input does not already contain encoded characters
 * by calling canonicalize. Validator implementations should call canonicalize on user input
 * <b>before</b> validating to prevent encoded attacks.
 * <p>
 * All of the methods must use a "whitelist" or "positive" security model.
 * For the encoding methods, this means that all characters should be encoded, except for a specific list of
 * "immune" characters that are known to be safe.
 * <p>
 * The Encoder performs two key functions, encoding and decoding. These functions rely
 * on a set of codecs that can be found in the org.owasp.esapi.codecs package. These include:
 * <ul><li>CSS Escaping</li>
 * <li>HTMLEntity Encoding</li>
 * <li>JavaScript Escaping</li>
 * <li>MySQL Escaping</li>
 * <li>Oracle Escaping</li>
 * <li>Percent Encoding (aka URL Encoding)</li>
 * <li>Unix Escaping</li>
 * <li>VBScript Escaping</li>
 * <li>Windows Encoding</li></ul>
 * <p>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Encoder {

    /**
     * Encode data for insertion inside a data value or function argument in JavaScript. Including user data 
     * directly inside a script is quite dangerous. Great care must be taken to prevent including user data
     * directly into script code itself, as no amount of encoding will prevent attacks there.
     * 
     * Please note there are some JavaScript functions that can never safely receive untrusted data 
     * as input – even if the user input is encoded.
     * 
     * For example:
     * 
     *  <script>
     *  window.setInterval('<%= EVEN IF YOU ENCODE UNTRUSTED DATA YOU ARE XSSED HERE %>');
     *  </script>
     * 
     * @param input 
     *          the text to encode for JavaScript
     * 
     * @return input encoded for use in JavaScript
     */
	String encodeForJavaScript(String input);


}
