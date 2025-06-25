package at.asitplus.openid

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.dif.FormatHolder
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class RelyingPartyMetadata(
    /**
     * OIDC Registration: REQUIRED. Array of Redirection URI values used by the Client. One of these registered
     * Redirection URI values MUST exactly match the `redirect_uri` parameter value used in each Authorization Request,
     * with the matching performed as described in Section 6.2.1 of (RFC3986) (Simple String Comparison).
     */
    @SerialName("redirect_uris")
    val redirectUris: List<String>? = null,

    /**
     * OIDC Registration: OPTIONAL. Client's JWK Set document, passed by value. The semantics of the `jwks` parameter
     * are the same as the [jsonWebKeySetUrl] parameter, other than that the JWK Set is passed by value, rather than by
     * reference. This parameter is intended only to be used by Clients that, for some reason, are unable to use the
     * [jsonWebKeySetUrl] parameter, for instance, by native applications that might not have a location to host the
     * contents of the JWK Set. If a Client can use [jsonWebKeySetUrl], it MUST NOT use [jsonWebKeySet]. One significant
     * downside of [jsonWebKeySet] is that it does not enable key rotation (which [jsonWebKeySetUrl] does, as described
     * in Section 10 of OpenID Connect Core 1.0). The [jsonWebKeySetUrl] and [jsonWebKeySet] parameters MUST NOT be used
     * together. The JWK Set MUST NOT contain private or symmetric key values.
     */
    @SerialName("jwks")
    val jsonWebKeySet: JsonWebKeySet? = null,

    /**
     * OIDC Registration: OPTIONAL. URL for the Client's JWK Set document, which MUST use the https scheme. If the
     * Client signs requests to the Server, it contains the signing key(s) the Server uses to validate signatures from
     * the Client. The JWK Set MAY also contain the Client's encryption keys(s), which are used by the Server to encrypt
     * responses to the Client. When both signing and encryption keys are made available, a use (public key use)
     * parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage.
     * Although some algorithms allow the same key to be used for both signatures and encryption, doing so is
     * NOT RECOMMENDED, as it is less secure. The JWK `x5c` parameter MAY be used to provide X.509 representations of
     * keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate.
     * The JWK Set MUST NOT contain private or symmetric key values.
     */
    @SerialName("jwks_uri")
    val jsonWebKeySetUrl: String? = null,

    /**
     * OIDC Registration: OPTIONAL. JWS alg algorithm REQUIRED for signing the ID Token issued to this Client.
     * The value none MUST NOT be used as the ID Token alg value unless the Client uses only Response Types that return
     * no ID Token from the Authorization Endpoint (such as when only using the Authorization Code Flow).
     * The default, if omitted, is RS256.
     * The public key for validating the signature is provided by retrieving the JWK Set referenced by the `jwks_uri`
     * element from OpenID Connect Discovery 1.0.
     */
    @SerialName("id_token_signed_response_alg")
    val idTokenSignedResponseAlgString: String? = null,

    /**
     * OID JARM: JWS (RFC7515) `alg` algorithm JWA (RFC7518). REQUIRED for signing authorization responses.
     * If this is specified, the response will be signed using JWS and the configured algorithm.
     * The algorithm `none` is not allowed. The default, if omitted, is RS256.
     */
    @SerialName("authorization_signed_response_alg")
    val authorizationSignedResponseAlgString: String? = null,

    /**
     * OID JARM: JWE (RFC7516) `alg` algorithm JWA (RFC7518). REQUIRED for encrypting authorization responses.
     * If both signing and encryption are requested, the response will be signed then encrypted, with the result being
     * a Nested JWT, as defined in JWT (RFC7519). The default, if omitted, is that no encryption is performed.
     */
    @SerialName("authorization_encrypted_response_alg")
    val authorizationEncryptedResponseAlgString: String? = null,

    /**
     * OID JARM: JWE (RFC7516) `enc` algorithm JWA (RFC7518). REQUIRED for encrypting authorization responses.
     * If [authorizationEncryptedResponseAlg] is specified, the default for this value is A128CBC-HS256.
     * When [authorizationEncryptedResponseEncoding] is included, [authorizationEncryptedResponseAlg] MUST also be
     * provided.
     */
    @SerialName("authorization_encrypted_response_enc")
    val authorizationEncryptedResponseEncodingString: String? = null,

    /**
     * OIDC Registration: OPTIONAL. JWE alg algorithm REQUIRED for encrypting the ID Token issued to this Client.
     * If this is requested, the response will be signed then encrypted, with the result being a Nested JWT.
     * The default, if omitted, is that no encryption is performed.
     */
    @SerialName("id_token_encrypted_response_alg")
    val idTokenEncryptedResponseAlgString: String? = null,

    /**
     * OIDC Registration: OPTIONAL. JWE enc algorithm REQUIRED for encrypting the ID Token issued to this Client.
     * If [idTokenEncryptedResponseAlg] is specified, the default value is A128CBC-HS256.
     * When [idTokenEncryptedResponseEncoding] is included, [idTokenEncryptedResponseAlg] MUST also be provided.
     */
    @SerialName("id_token_encrypted_response_enc")
    val idTokenEncryptedResponseEncodingString: String? = null,

    /**
     * OIDC SIOPv2: REQUIRED. A JSON array of strings representing URI scheme identifiers and optionally method names of
     * supported Subject Syntax Types.
     * Valid values include `urn:ietf:params:oauth:jwk-thumbprint`, `did:example` and others.
     */
    @SerialName("subject_syntax_types_supported")
    val subjectSyntaxTypesSupported: Set<String>? = null,

    /**
     * OID4VP: REQUIRED. An object defining the formats and proof types of Verifiable Presentations and Verifiable
     * Credentials that a Verifier supports. Deployments can extend the formats supported, provided Issuers, Holders
     * and Verifiers all understand the new format.
     */
    @SerialName("vp_formats")
    val vpFormats: FormatHolder? = null,

    /**
     * OID4VP: OPTIONAL. JSON String identifying the Client Identifier scheme. The value range defined by this
     * specification is `pre-registered`, `redirect_uri`, `entity_id`, `did`.
     * If omitted, the default value is `pre-registered`.
     */
    @SerialName("client_id_scheme")
    val clientIdScheme: OpenIdConstants.ClientIdScheme? = OpenIdConstants.ClientIdScheme.PreRegistered,
) {

    fun serialize() = odcJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            odcJsonSerializer.decodeFromString<RelyingPartyMetadata>(it)
        }.wrap()
    }

    /**
     * OID JARM: JWE (RFC7516) `alg` algorithm JWA (RFC7518). REQUIRED for encrypting authorization responses.
     * If both signing and encryption are requested, the response will be signed then encrypted, with the result being
     * a Nested JWT, as defined in JWT (RFC7519). The default, if omitted, is that no encryption is performed.
     */
    @Transient
    val authorizationEncryptedResponseAlg: JweAlgorithm? = authorizationEncryptedResponseAlgString
        ?.let { s -> JweAlgorithm.entries.firstOrNull { it.identifier == s } }

    /**
     * OIDC Registration: OPTIONAL. JWE alg algorithm REQUIRED for encrypting the ID Token issued to this Client.
     * If this is requested, the response will be signed then encrypted, with the result being a Nested JWT.
     * The default, if omitted, is that no encryption is performed.
     */
    @Transient
    val idTokenEncryptedResponseAlg: JweAlgorithm? = idTokenEncryptedResponseAlgString
        ?.let { s -> JweAlgorithm.entries.firstOrNull { it.identifier == s } }

    /**
     * OIDC Registration: OPTIONAL. JWS alg algorithm REQUIRED for signing the ID Token issued to this Client.
     * The value none MUST NOT be used as the ID Token alg value unless the Client uses only Response Types that return
     * no ID Token from the Authorization Endpoint (such as when only using the Authorization Code Flow).
     * The default, if omitted, is RS256.
     * The public key for validating the signature is provided by retrieving the JWK Set referenced by the `jwks_uri`
     * element from OpenID Connect Discovery 1.0.
     */
    @Transient
    val idTokenSignedResponseAlg: JwsAlgorithm? = idTokenSignedResponseAlgString
        ?.let { s -> JwsAlgorithm.entries.firstOrNull { it.identifier == s } }

    /**
     * OID JARM: JWS (RFC7515) `alg` algorithm JWA (RFC7518). REQUIRED for signing authorization responses.
     * If this is specified, the response will be signed using JWS and the configured algorithm.
     * The algorithm `none` is not allowed. The default, if omitted, is RS256.
     */
    @Transient
    val authorizationSignedResponseAlg: JwsAlgorithm? = authorizationSignedResponseAlgString
        ?.let { s -> JwsAlgorithm.entries.firstOrNull { it.identifier == s } }

    /**
     * OID JARM: JWE (RFC7516) `enc` algorithm JWA (RFC7518). REQUIRED for encrypting authorization responses.
     * If [authorizationEncryptedResponseAlg] is specified, the default for this value is A128CBC-HS256.
     * When [authorizationEncryptedResponseEncoding] is included, [authorizationEncryptedResponseAlg] MUST also be
     * provided.
     */
    @Transient
    val authorizationEncryptedResponseEncoding: JweEncryption? = authorizationEncryptedResponseEncodingString
        ?.let { s -> JweEncryption.entries.firstOrNull { it.identifier == s } }

    /**
     * OIDC Registration: OPTIONAL. JWE enc algorithm REQUIRED for encrypting the ID Token issued to this Client.
     * If [idTokenEncryptedResponseAlg] is specified, the default value is A128CBC-HS256.
     * When [idTokenEncryptedResponseEncoding] is included, [idTokenEncryptedResponseAlg] MUST also be provided.
     */
    @Transient
    val idTokenEncryptedResponseEncoding: JweEncryption? = idTokenEncryptedResponseEncodingString
        ?.let { s -> JweEncryption.entries.firstOrNull { it.identifier == s } }
}

