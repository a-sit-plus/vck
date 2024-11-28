package at.asitplus.wallet.lib.data.rfc9110

import kotlin.jvm.JvmInline

/**
 * HTTP field values consist of a sequence of characters in a format defined by the field's
 * grammar. Each field's grammar is usually defined using ABNF ([RFC5234]).
 *
 *   field-value    = *field-content
 *   field-content  = field-vchar
 *                    [ 1*( SP / HTAB / field-vchar ) field-vchar ]
 *   field-vchar    = VCHAR / obs-text
 *   obs-text       = %x80-FF
 *
 * A field value does not include leading or trailing whitespace. When a specific version of HTTP
 * allows such whitespace to appear in a message, a field parsing implementation MUST exclude such
 * whitespace prior to evaluating the field value. Field values are usually constrained to the
 * range of US-ASCII characters [USASCII]. Fields needing a greater range of characters can use an
 * encoding, such as the one defined in [RFC8187]. Historically, HTTP allowed field content with
 * text in the ISO-8859-1 charset [ISO-8859-1], supporting other charsets only through use of
 * [RFC2047] encoding. Specifications for newly defined fields SHOULD limit their values to visible
 * US-ASCII octets (VCHAR), SP, and HTAB. A recipient SHOULD treat other allowed octets in field
 * content (i.e., obs-text) as opaque data. Field values containing CR, LF, or NUL characters are
 * invalid and dangerous, due to the varying ways that implementations might parse and interpret
 * those characters; a recipient of CR, LF, or NUL within a field value MUST either reject the
 * message or replace each of those characters with SP before further processing or forwarding of
 * that message. Field values containing other CTL characters are also invalid; however, recipients
 * MAY retain such characters for the sake of robustness when they appear within a safe context
 * (e.g., an application-specific quoted string that will not be processed by any downstream HTTP
 * parser). Fields that only anticipate a single member as the field value are referred to as
 * "singleton fields". Fields that allow multiple members as the field value are referred to as
 * "list-based fields". The list operator extension of Section 5.6.1 is used as a common notation
 * for defining field values that can contain multiple members. Because commas (",") are used as
 * the delimiter between members, they need to be treated with care if they are allowed as data
 * within a member. This is true for both list-based and singleton fields, since a singleton field
 * might be erroneously sent with multiple members and detecting such errors improves
 * interoperability. Fields that expect to contain a comma within a member, such as within an
 * HTTP-date or URI-reference element, ought to be defined with delimiters around that element
 * to distinguish any comma within that data from potential list separators. For example, a textual
 * date and a URI (either of which might contain a comma) could be safely carried in list-based
 * field values like these:
 *
 * Example-URIs: "http://example.com/a.html,foo",
 *               "http://without-a-comma.example.com/"
 * Example-Dates: "Sat, 04 May 1996", "Wed, 14 Sep 2005"
 *
 * Note that double-quote delimiters are almost always used with the quoted-string production
 * (Section 5.6.4); using a different syntax inside double-quotes will likely cause unnecessary
 * confusion. Many fields (such as Content-Type, defined in Section 8.3) use a common syntax for
 * parameters that allows both unquoted (token) and quoted (quoted-string) syntax for a parameter
 * value (Section 5.6.6). Use of common syntax allows recipients to reuse existing parser
 * components. When allowing both forms, the meaning of a parameter value ought to be the same
 * whether it was received as a token or a quoted string.
 *
 * Note: For defining field value syntax, this specification uses an ABNF rule named after the
 * field name to define the allowed grammar for that field's value (after said value has been
 * extracted from the underlying messaging syntax and multiple instances combined into a list).
 */
@JvmInline
value class HttpFieldValue(val value: String) {
    override fun toString() = value.trim()

    // TODO: validation?
}