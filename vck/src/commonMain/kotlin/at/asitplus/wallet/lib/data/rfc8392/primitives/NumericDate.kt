package at.asitplus.wallet.lib.data.rfc8392.primitives

/**
 *    NumericDate
 *       The "NumericDate" term in this specification has the same meaning
 *       and processing rules as the JWT "NumericDate" term defined in
 *       Section 2 of [RFC7519], except that it is represented as a CBOR
 *       numeric date (from Section 2.4.1 of [RFC7049]) instead of a JSON
 *       number.  The encoding is modified so that the leading tag 1
 *       (epoch-based date/time) MUST be omitted.
 *
 *  Note: JWT NumericDate is big enough to hold any currently interesting
 *  instant with millisecond precision. No need to define a new numeric date format for now.
 */
typealias NumericDate = at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate