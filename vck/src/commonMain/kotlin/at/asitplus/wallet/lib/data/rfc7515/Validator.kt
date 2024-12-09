package at.asitplus.wallet.lib.data.rfc7515

import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElement
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsAlgorithmHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsContentTypeHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsJsonWebKeyHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsJsonWebKeySetUrlHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsKeyIdHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsTypeHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsX509CertificateChainHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsX509CertificateSha1ThumbprintHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsX509CertificateSha256ThumbprintHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsX509UrlHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7515.primitives.FlattenedJsonJws
import at.asitplus.wallet.lib.data.rfc7515.primitives.GeneralJsonJws
import at.asitplus.wallet.lib.data.rfc7515.primitives.GeneralJsonJwsSignature
import at.asitplus.wallet.lib.data.rfc7515.primitives.JwsValidationResult
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.VerifierJwsService
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject

/**
 * 5.2.  Message Signature or MAC Validation
 *
 *    When validating a JWS, the following steps are performed.  The order
 *    of the steps is not significant in cases where there are no
 *    dependencies between the inputs and outputs of the steps.  If any of
 *    the listed steps fails, then the signature or MAC cannot be
 *    validated.
 *
 *    When there are multiple JWS Signature values, it is an application
 *    decision which of the JWS Signature values must successfully validate
 *    for the JWS to be accepted.  In some cases, all must successfully
 *    validate, or the JWS will be considered invalid.  In other cases,
 *    only a specific JWS Signature value needs to be successfully
 *    validated.  However, in all cases, at least one JWS Signature value
 *    MUST successfully validate, or the JWS MUST be considered invalid.
 *
 *    1.  Parse the JWS representation to extract the serialized values for
 *        the components of the JWS.  When using the JWS Compact
 *        Serialization, these components are the base64url-encoded
 *        representations of the JWS Protected Header, the JWS Payload, and
 *        the JWS Signature, and when using the JWS JSON Serialization,
 *        these components also include the unencoded JWS Unprotected
 *        Header value.  When using the JWS Compact Serialization, the JWS
 *        Protected Header, the JWS Payload, and the JWS Signature are
 *        represented as base64url-encoded values in that order, with each
 *        value being separated from the next by a single period ('.')
 *        character, resulting in exactly two delimiting period characters
 *        being used. The JWS JSON Serialization is described in
 *        Section 7.2.
 *
 *    2.  Base64url-decode the encoded representation of the JWS Protected
 *        Header, following the restriction that no line breaks,
 *        whitespace, or other additional characters have been used.
 *
 *    3.  Verify that the resulting octet sequence is a UTF-8-encoded
 *        representation of a completely valid JSON object conforming to
 *        RFC 7159 [RFC7159]; let the JWS Protected Header be this JSON
 *        object.
 *
 *    4.  If using the JWS Compact Serialization, let the JOSE Header be
 *        the JWS Protected Header.  Otherwise, when using the JWS JSON
 *        Serialization, let the JOSE Header be the union of the members of
 *        the corresponding JWS Protected Header and JWS Unprotected
 *        Header, all of which must be completely valid JSON objects.
 *        During this step, verify that the resulting JOSE Header does not
 *        contain duplicate Header Parameter names.  When using the JWS
 *        JSON Serialization, this restriction includes that the same
 *        Header Parameter name also MUST NOT occur in distinct JSON object
 *        values that together comprise the JOSE Header.
 *
 *    5.  Verify that the implementation understands and can process all
 *        fields that it is required to support, whether required by this
 *        specification, by the algorithm being used, or by the "crit"
 *        Header Parameter value, and that the values of those parameters
 *        are also understood and supported.
 *
 *    6.  Base64url-decode the encoded representation of the JWS Payload,
 *        following the restriction that no line breaks, whitespace, or
 *        other additional characters have been used.
 *
 *    7.  Base64url-decode the encoded representation of the JWS Signature,
 *        following the restriction that no line breaks, whitespace, or
 *        other additional characters have been used.
 *
 *    8.  Validate the JWS Signature against the JWS Signing Input
 *        ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
 *        BASE64URL(JWS Payload)) in the manner defined for the algorithm
 *        being used, which MUST be accurately represented by the value of
 *        the "alg" (algorithm) Header Parameter, which MUST be present.
 *        See Section 10.6 for security considerations on algorithm
 *        validation.  Record whether the validation succeeded or not.
 *
 *    9.  If the JWS JSON Serialization is being used, repeat this process
 *        (steps 4-8) for each digital signature or MAC value contained in
 *        the representation.
 *
 *    10. If none of the validations in step 9 succeeded, then the JWS MUST
 *        be considered invalid.  Otherwise, in the JWS JSON Serialization
 *        case, return a result to the application indicating which of the
 *        validations succeeded and failed.  In the JWS Compact
 *        Serialization case, the result can simply indicate whether or not
 *        the JWS was successfully validated.
 *
 *    Finally, note that it is an application decision which algorithms may
 *    be used in a given context.  Even if a JWS can be successfully
 *    validated, unless the algorithm(s) used in the JWS are acceptable to
 *    the application, it SHOULD consider the JWS to be invalid.
 */
fun VerifierJwsService.verifyJws(
    input: String,
): JwsValidationResult {
    val message = input

    val (payload, signaturesToBeChecked) = if (input.startsWith("{")) {
        val jsonJwsSigned = vckJsonSerializer.decodeFromString<JsonObject>(message)
        val (payload, signatures) = if (jsonJwsSigned.containsKey("signatures")) {
            val jws = vckJsonSerializer.decodeFromJsonElement<GeneralJsonJws>(jsonJwsSigned)
            jws.payload to jws.signatures
        } else {
            val jws = vckJsonSerializer.decodeFromJsonElement<FlattenedJsonJws>(jsonJwsSigned)
            jws.payload to listOf(
                GeneralJsonJwsSignature(
                    protected = jws.protected,
                    header = jws.header,
                    signature = jws.signature,
                )
            )
        }
        payload to signatures.map {
            it.joseHeader to FlattenedJsonJws(
                payload = payload,
                header = it.header,
                protected = it.protected,
                signature = it.signature,
            ).toJwsSigned()
        }
    } else {
        val joseHeader = message.split(".").first().let {
            vckJsonSerializer.decodeFromString<JsonObject>(it)
        }
        val jwsSigned = JwsSigned.deserialize(message).getOrThrow()
        jwsSigned.payload to listOf(
            joseHeader to jwsSigned,
        )
    }

    return JwsValidationResult(
        commonHeaders = signaturesToBeChecked.map {
            it.first
        }.reduce { acc, joseHeader ->
            acc.filterKeys {
                it in joseHeader.keys
            }.toJsonElement().jsonObject
        },
        payload = payload,
        signatureValidities = signaturesToBeChecked.map { (joseHeader, jwsSigned) ->
            verifyJwsObject(jwsSigned) && validateJwsHeaders(
                joseHeader,
                jwsSigned.header
            )
        }
    )
}

private fun VerifierJwsService.validateJwsHeaders(
    joseHeader: JsonObject,
    jwsHeader: JwsHeader
): Boolean {
    // TODO: 5.  Verify that the implementation understands and can process all
    //       fields that it is required to support, whether required by this
    //       specification, by the algorithm being used, or by the "crit"
    //       Header Parameter value, and that the values of those parameters
    //       are also understood and supported.
    val headersToBeSupported = listOf(
        // required by the `crit` header parameter value
        jwsHeader.critical?.toMutableList() ?: mutableListOf(),
    ) + listOf(
        // required by this specification
        JwsAlgorithmHeaderParameterSpecification.NAME,
        JwsContentTypeHeaderParameterSpecification.NAME,
        JwsJsonWebKeyHeaderParameterSpecification.NAME,
        JwsJsonWebKeySetUrlHeaderParameterSpecification.NAME,
        JwsKeyIdHeaderParameterSpecification.NAME,
        JwsTypeHeaderParameterSpecification.NAME,
        JwsX509CertificateChainHeaderParameterSpecification.NAME,
        JwsX509CertificateSha1ThumbprintHeaderParameterSpecification.NAME,
        JwsX509CertificateSha256ThumbprintHeaderParameterSpecification.NAME,
        JwsX509UrlHeaderParameterSpecification.NAME,
    )
    val availableHeaders = joseHeader.keys

    // TODO: maybe be more expressive with information leaked to the library user
    return availableHeaders.intersect(headersToBeSupported.toSet()).all { key ->
        joseHeader.get(key)!!.let { value ->
            supportedHeaders.get(key)?.invoke(value) == true
        }
    }
}