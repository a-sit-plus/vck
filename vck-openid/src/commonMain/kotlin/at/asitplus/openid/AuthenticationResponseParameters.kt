package at.asitplus.openid

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.data.InstantLongSerializer
import at.asitplus.dif.PresentationSubmission
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonElement

/**
 * Contents of an OIDC Authentication Response.
 *
 * Usually, these parameters are appended to the redirect URL (`redirect_uri`) of the Relying Party.
 */
@Serializable
data class AuthenticationResponseParameters(

    /**
     * OAuth2.0: REQUIRED. The authorization code generated by the authorization server. The authorization code MUST
     * expire shortly after it is issued to mitigate the risk of leaks. A maximum authorization code lifetime of 10
     * minutes is RECOMMENDED. The client MUST NOT use the authorization code more than once. If an authorization code
     * is used more than once, the authorization server MUST deny the request and SHOULD revoke (when possible) all
     * tokens previously issued based on that authorization code. The authorization code is bound to the client
     * identifier and redirection URI.
     */
    val code: String? = null,

    /**
     * [IdToken] serialized, wrapped inside a JWS.
     */
    @SerialName("id_token")
    val idToken: String? = null,

    /**
     * OID4VP: REQUIRED. JSON String or JSON object that MUST contain a single Verifiable Presentation or an array of
     * JSON Strings and JSON objects each of them containing a Verifiable Presentations. Each Verifiable Presentation
     * MUST be represented as a JSON string (that is a Base64url encoded value) or a JSON object depending on a format
     * as defined in Annex E of OpenID.VCI. When a single Verifiable Presentation is returned, the array syntax MUST NOT
     * be used. If Appendix E of OpenID.VCI defines a rule for encoding the respective Credential format in the
     * Credential Response, this rules MUST also be followed when encoding Credentials of this format in the `vp_token`
     * response parameter. Otherwise, this specification does not require any additional encoding when a Credential
     * format is already represented as a JSON object or a JSON string.
     */
    @SerialName("vp_token")
    val vpToken: JsonElement? = null,

    /**
     * OID4VP: REQUIRED. The presentation_submission element as defined in DIF.PresentationExchange. It contains
     * mappings between the requested Verifiable Credentials and where to find them within the returned VP Token.
     * This is expressed via elements in the `descriptor_map` array, known as Input Descriptor Mapping Objects. These
     * objects contain a field called path, which, for this specification, MUST have the value `$` (top level root path)
     * when only one Verifiable Presentation is contained in the VP Token, and MUST have the value `$[n]` (indexed path
     * from root) when there are multiple Verifiable Presentations, where `n` is the index to select. The `path_nested`
     * object inside an Input Descriptor Mapping Object is used to describe how to find a returned Credential within a
     * Verifiable Presentation, and the value of the path field in it will ultimately depend on the credential format.
     * Non-normative examples can be found further in this section.
     */
    @SerialName("presentation_submission")
    val presentationSubmission: PresentationSubmission? = null,

    /**
     * OAuth2.0: REQUIRED if the `state` parameter was present in the client authorization request. The exact value
     * received from the client.
     */
    @SerialName("state")
    val state: String? = null,

    /**
     * JARM: REQUIRED, the issuer URL of the authorization server that created the response.
     */
    @SerialName("iss")
    val issuer: String? = null,

    /**
     * JARM: REQUIRED, the `client_id` of the client the response is intended for
     */
    @SerialName("aud")
    val audience: String? = null,

    /**
     * JARM: REQUIRED, expiration of the JWT. A maximum JWT lifetime of 10 minutes is RECOMMENDED.
     */
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant? = null,

    /**
     * JARM: Holds all other parameters inside an JWT.
     */
    @SerialName("response")
    val response: String? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<AuthenticationResponseParameters>(it)
        }.wrap()
    }
}
