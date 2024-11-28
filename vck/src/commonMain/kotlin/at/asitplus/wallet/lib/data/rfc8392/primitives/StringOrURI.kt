package at.asitplus.wallet.lib.data.rfc8392.primitives

/**
 *    StringOrURI
 *       The "StringOrURI" term in this specification has the same meaning
 *       and processing rules as the JWT "StringOrURI" term defined in
 *       Section 2 of [RFC7519], except that it is represented as a CBOR
 *       text string instead of a JSON text string.
 *
 *  Note: No additional holder class is required, the serializer can be reused for cbor.
 */
typealias StringOrURI = at.asitplus.wallet.lib.data.rfc7519.primitives.StringOrURI