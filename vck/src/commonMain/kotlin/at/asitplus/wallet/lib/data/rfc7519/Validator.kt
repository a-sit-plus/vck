package at.asitplus.wallet.lib.data.rfc7519

import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsContentTypeHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7515.verifyJws
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.third_party.kotlin.decodeBase64UrlString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * 7.2.  Validating a JWT
 *
 *    When validating a JWT, the following steps are performed.  The order
 *    of the steps is not significant in cases where there are no
 *    dependencies between the inputs and outputs of the steps.  If any of
 *    the listed steps fail, then the JWT MUST be rejected -- that is,
 *    treated by the application as an invalid input.
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
fun VerifierJwsService.validateJwt(
    input: String,
): JsonObject {
    var message = input

    do {
        if (!message.contains('.')) {
            throw IllegalArgumentException("Argument `input` must contain at least one dot (`.`).")
        }

        val validationResult = when (message.count { it == '.' }) {
            JwsSigned.SEGMENT_COUNT -> {
                val validationResult = verifyJws(message).also {
                    if (it.isValid != true) {
                        throw IllegalStateException("Argument `input` or any of its nested tokens has an invalid signature.")
                    }
                }

                validationResult
            }

            JweEncrypted.SEGMENT_COUNT -> {
                TODO("Support validation of JWE.")
            }

            else -> throw IllegalArgumentException("Argument `input` must be comprised of either 3 or 5 dot-separated segments.")
        }

        val containsJwt = validationResult.commonHeaders[JwsContentTypeHeaderParameterSpecification.NAME] == JsonPrimitive(
            JwsContentTypeConstants.JWT
        )
        if (containsJwt) {
            message = validationResult.payload.decodeToString()
        }
    } while (containsJwt)

    return joseCompliantSerializer.decodeFromString<JsonObject>(message.decodeBase64UrlString())
}