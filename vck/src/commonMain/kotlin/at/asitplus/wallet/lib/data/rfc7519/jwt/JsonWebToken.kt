package at.asitplus.wallet.lib.data.rfc7519.jwt

import at.asitplus.wallet.lib.data.rfc7515.JsonWebSignatureVerifier
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsContentTypeHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7515.primitives.CompactJsonWebSignature
import at.asitplus.wallet.lib.data.rfc7516.JsonWebEncryptionSpecification
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.third_party.kotlin.decodeBase64Url
import at.asitplus.wallet.lib.third_party.kotlin.decodeBase64UrlString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.jvm.JvmInline

@JvmInline
value class JsonWebToken(val value: String) {
    /**
     * 7.2.  Validating a JWT
     *
     *    When validating a JWT, the following steps are performed.  The order
     *    of the steps is not significant in cases where there are no
     *    dependencies between the inputs and outputs of the steps.  If any of
     *    the listed steps fail, then the JWT MUST be rejected -- that is,
     *    treated by the application as an invalid input.
     *
     *    1.   Verify that the JWT contains at least one period ('.')
     *         character.
     *
     *    2.   Let the Encoded JOSE Header be the portion of the JWT before the
     *         first period ('.') character.
     *
     *    3.   Base64url decode the Encoded JOSE Header following the
     *         restriction that no line breaks, whitespace, or other additional
     *         characters have been used.
     *
     *    4.   Verify that the resulting octet sequence is a UTF-8-encoded
     *         representation of a completely valid JSON object conforming to
     *         RFC 7159 [RFC7159]; let the JOSE Header be this JSON object.
     *
     *    5.   Verify that the resulting JOSE Header includes only parameters
     *         and values whose syntax and semantics are both understood and
     *         supported or that are specified as being ignored when not
     *         understood.
     *
     *    6.   Determine whether the JWT is a JWS or a JWE using any of the
     *         methods described in Section 9 of [JWE].
     *
     *    7.   Depending upon whether the JWT is a JWS or JWE, there are two
     *         cases:
     *
     *         *  If the JWT is a JWS, follow the steps specified in [JWS] for
     *            validating a JWS.  Let the Message be the result of base64url
     *            decoding the JWS Payload.
     *
     *         *  Else, if the JWT is a JWE, follow the steps specified in
     *            [JWE] for validating a JWE.  Let the Message be the resulting
     *            plaintext.
     *
     *
     *    8.   If the JOSE Header contains a "cty" (content type) value of
     *         "JWT", then the Message is a JWT that was the subject of nested
     *         signing or encryption operations.  In this case, return to Step
     *         1, using the Message as the JWT.
     *
     *    9.   Otherwise, base64url decode the Message following the
     *         restriction that no line breaks, whitespace, or other additional
     *         characters have been used.
     *
     *    10.  Verify that the resulting octet sequence is a UTF-8-encoded
     *         representation of a completely valid JSON object conforming to
     *         RFC 7159 [RFC7159]; let the JWT Claims Set be this JSON object.
     *
     *    Finally, note that it is an application decision which algorithms may
     *    be used in a given context.  Even if a JWT can be successfully
     *    validated, unless the algorithms used in the JWT are acceptable to
     *    the application, it SHOULD reject the JWT.
     */
    suspend fun <T> validate(
        jsonWebSignatureVerifier: JsonWebSignatureVerifier,
        json: Json = Json,
    ): JsonObject {
        var message = value

        do {
            val segmentCount = message.count { it == '.' } + 1
            val joseHeader = message.substringBefore('.').decodeBase64Url().let {
                json.decodeFromString<JsonObject>(it.decodeToString())
            }

            val (content, isIntegrityGood) = when (segmentCount) {
                CompactJsonWebSignature.Specification.SEGMENT_COUNT -> {
                    val jws = CompactJsonWebSignature.deserialize(message)

                    val isSignatureValid = jsonWebSignatureVerifier(
                        header = joseHeader,
                        signatureInput = jws.signatureInput,
                        signature = jws.signature,
                    )

                    Pair(
                        jws.payload,
                        isSignatureValid,
                    )
                }

                JsonWebEncryptionSpecification.COMPACT_SERIALIZATION_SEGMENT_COUNT -> {
                    TODO("Support validation of JWE.")
                }

                else -> throw IllegalArgumentException("Argument `input` and all nested tokens must be comprised of either 3 or 5 dot-separated segments.")
            }

            if (!isIntegrityGood) {
                throw IllegalStateException("Integrity of the token cannot be guranteed for argument `input` or a nested token.")
            }

            val containsJwt =
                joseHeader[JwsContentTypeHeaderParameterSpecification.NAME] == JsonPrimitive(
                    JwsContentTypeConstants.JWT
                )

            message = content.decodeToString()
        } while (containsJwt)

        return json.decodeFromString<JsonObject>(message.decodeBase64UrlString())
    }
}