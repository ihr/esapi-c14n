/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This code within this file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Ivan Hristov <a href="http://ingini.org">ingini.org</a>
 * @created 2007
 */
package org.owasp.esapi.c14n;

/**
 * The interface provides canonicalization methods which ensures that the result does not contain encoded characters.
 * Validator implementations should call canonicalize on user input <b>before</b> validating to prevent encoded attacks.
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Canonicalizator {

	/**
     * This method strictly canonicalizes {@code input}. The meaning of "strictly" is that an {@link IllegalStateException}
     * will be thrown in case {@code input} is encoded multiple times or there is a mix encoding detected.
     *
	 * @see {@link Canonicalizator#canonicalize(String, boolean, boolean)}
	 * @see <a href="http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4">W3C specifications</a>
	 *
	 * @param input the text to canonicalize
	 * @return a String containing the canonicalized text
	 */
	String canonicalize(String input);


	/**
	 * Canonicalization is simply the operation of reducing a possibly encoded string down to its simplest form. This is
     * important, because attackers frequently use encoding to change their input in a way that will bypass validation
     * filters, but still be interpreted properly by the target of the attack. Note that data encoded more than once is
     * not something that a normal user would generate and should be regarded as an attack.
	 * <p>
     * Everyone <a href="http://cwe.mitre.org/data/definitions/180.html">says</a> you shouldn't do validation without
     * canonicalizing the data first. This is easier said than done. The canonicalize method can be used to simplify just
     * about any input down to its most basic form. Note that canonicalize doesn't handle Unicode issues, it focuses on
     * higher level encoding and escaping schemes. In addition to simple decoding, canonicalize also handles:
     * <ul><li>Perverse but legal variants of escaping schemes</li>
     * <li>Multiple escaping (%2526 or &#x26;lt;)</li>
     * <li>Mixed escaping (%26lt;)</li>
     * <li>Nested escaping (%%316 or &%6ct;)</li>
     * <li>All combinations of multiple, mixed, and nested encoding/escaping (%2&#x35;3c or &#x2526gt;)</li></ul>
     * <p>
     * Using canonicalize is simple. The default is just...
     * <pre>
     *     String clean = <Canonicalizator-instance>.canonicalize( request.getParameter("input"));
     * </pre>
     * //TODO the same can be done but from the MongoDB to the top (browser or other client)
     * You need to decode untrusted data so that it's safe for ANY downstream interpreter or decoder. For
     * example, if your data goes into a Windows command shell, then into a database, and then to a browser,
     * you're going to need to decode for all of those systems. You can build a custom encoder to canonicalize
     * for your application like this...
     * <pre>
     *     ArrayList list = new ArrayList();
     *     list.add( new WindowsCodec() );
     *     list.add( new MySQLCodec() );
     *     list.add( new PercentCodec() );
     *     Encoder encoder = new DefaultEncoder( list );
     *     String clean = encoder.canonicalize( request.getParameter( "input" ));
     * </pre>
     * In ESAPI, the Validator uses the canonicalize method before it does validation.  So all you need to
     * do is to validate as normal and you'll be protected against a host of encoded attacks.
     * <pre>
     *     String input = request.getParameter( "name" );
     *     String name = ESAPI.validator().isValidInput( "test", input, "FirstName", 20, false);
     * </pre>
     * However, the default canonicalize() method only decodes HTMLEntity, percent (URL) encoding, and JavaScript
     * encoding. If you'd like to use a custom canonicalizer with your validator, that's pretty easy too.
     * <pre>
     *     ... setup custom encoder as above
     *     Validator validator = new DefaultValidator( encoder );
     *     String input = request.getParameter( "name" );
     *     String name = validator.isValidInput( "test", input, "name", 20, false);
     * </pre>
     * Although ESAPI is able to canonicalize multiple, mixed, or nested encoding, it's safer to not accept
     * this stuff in the first place. In ESAPI, the default is "strict" mode that throws an IntrusionException
     * if it receives anything not single-encoded with a single scheme. This is configurable
     * in ESAPI.properties using the properties:
	 * <pre>
	 * Encoder.AllowMultipleEncoding=false
	 * Encoder.AllowMixedEncoding=false
	 * </pre>
	 * This method allows you to override the default behavior by directly specifying whether to restrict
	 * multiple or mixed encoding. Even if you disable restrictions, you'll still get
     * warning messages in the log about each multiple encoding and mixed encoding received.
     * <pre>
     *     // disabling strict mode to allow mixed encoding
     *     String url = ESAPI.encoder().canonicalize( request.getParameter("url"), false, false);
     * </pre>
	 *
	 * @see <a href="http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4">W3C specifications</a>
	 *
	 * @param input
	 * 		the text to canonicalize
	 * @param restrictMultiple
	 * 		true if checking for multiple encoding is desired, false otherwise
	 * @param restrictMixed
	 * 		true if checking for mixed encoding is desired, false otherwise
	 *
	 * @return a String containing the canonicalized text
	 */
	String canonicalize(String input, boolean restrictMultiple, boolean restrictMixed);


}
