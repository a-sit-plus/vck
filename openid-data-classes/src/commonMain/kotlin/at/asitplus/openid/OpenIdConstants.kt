package at.asitplus.openid

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object OpenIdConstants {

    const val ID_TOKEN = "id_token"

    const val VP_TOKEN = "vp_token"

    const val GRANT_TYPE_CODE = "code"

    const val GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"

    const val GRANT_TYPE_PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

    const val GRANT_TYPE_REFRESH_TOKEN = "refresh_token"

    const val TOKEN_PREFIX_BEARER = "Bearer "

    const val TOKEN_PREFIX_DPOP = "DPoP "

    const val TOKEN_TYPE_BEARER = "bearer"

    const val TOKEN_TYPE_DPOP = "DPoP"

    const val URN_TYPE_JWK_THUMBPRINT = "urn:ietf:params:oauth:jwk-thumbprint"

    const val BINDING_METHOD_COSE_KEY = "cose_key"

    const val PREFIX_DID_KEY = "did:key"

    /** OID4VCI support binding keys to [at.asitplus.signum.indispensable.josef.JsonWebKey] */
    const val BINDING_METHOD_JWK = "jwk"

    const val PATH_WELL_KNOWN_CREDENTIAL_ISSUER = "/.well-known/openid-credential-issuer"

    const val PATH_WELL_KNOWN_OPENID_CONFIGURATION = "/.well-known/openid-configuration"

    const val PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER = "/.well-known/oauth-authorization-server"

    const val PATH_WELL_KNOWN_JWT_VC_ISSUER_METADATA = "/.well-known/jwt-vc-issuer"

    const val PATH_WELL_KNOWN_JAR_ISSUER = "/.well-known/jar-issuer"

    const val SCOPE_OPENID = "openid"

    const val SCOPE_PROFILE = "profile"

    const val CODE_CHALLENGE_METHOD_SHA256 = "S256"

    const val PROOF_JWT_TYPE = "openid4vci-proof+jwt"

    const val KEY_ATTESTATION_JWT_TYPE = "key-attestation+jwt"

    const val AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH = "attest_jwt_client_auth"

    const val PARAMETER_PROMPT = "prompt"

    const val PARAMETER_PROMPT_LOGIN = "login"

    const val DC_API_OID4VP_PROTOCOL_IDENTIFIER = "openid4vp"


    @Serializable(with = ProofType.Serializer::class)
    sealed class ProofType(val stringRepresentation: String) {
        override fun toString(): String = this::class.simpleName + "(" + stringRepresentation + ")"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ProofType) return false
            return other.stringRepresentation == stringRepresentation
        }

        override fun hashCode(): Int {
            return stringRepresentation.hashCode()
        }

        companion object {
            private const val STRING_JWT = "jwt"
            private const val STRING_ATTESTATION = "attestation"
        }

        /**
         * Proof type `jwt` in [at.asitplus.openid.CredentialRequestProof]
         */
        object JWT : ProofType(STRING_JWT)

        /**
         * Proof type `attestation` in [at.asitplus.openid.CredentialRequestProof]
         */
        object ATTESTATION : ProofType(STRING_ATTESTATION)

        /**
         * Any proof type not natively supported by this library
         */
        class Other(stringRepresentation: String) : ProofType(stringRepresentation)

        object Serializer : KSerializer<ProofType> {
            override val descriptor: SerialDescriptor =
                PrimitiveSerialDescriptor(serialName = "ProofType", PrimitiveKind.STRING)

            override fun deserialize(decoder: Decoder): ProofType = when (val str = decoder.decodeString()) {
                STRING_JWT -> JWT
                STRING_ATTESTATION -> ATTESTATION
                else -> Other(str)
            }

            override fun serialize(encoder: Encoder, value: ProofType) {
                encoder.encodeString(value.stringRepresentation)
            }
        }
    }

    /**
     * Constants from OID4VP
     */
    @Serializable(with = ClientIdScheme.Serializer::class)
    sealed class ClientIdScheme(val stringRepresentation: String) {

        val prefix = "$stringRepresentation:"

        override fun toString(): String = this::class.simpleName + "(" + stringRepresentation + ")"

        override fun hashCode(): Int {
            return stringRepresentation.hashCode()
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ClientIdScheme) return false
            return other.stringRepresentation == stringRepresentation
        }

        companion object {
            private const val STRING_PRE_REGISTERED = "pre-registered"
            private const val STRING_REDIRECT_URI = "redirect_uri"
            private const val STRING_X509_SAN_DNS = "x509_san_dns"
            private const val STRING_X509_SAN_URI = "x509_san_uri"
            private const val STRING_ENTITY_ID = "entity_id"
            private const val STRING_DID = "did"
            private const val STRING_VERIFIER_ATTESTATION = "verifier_attestation"

            fun decodeFromClientId(clientId: String) = when (clientId.substringBefore(":")) {
                STRING_REDIRECT_URI -> RedirectUri
                STRING_X509_SAN_DNS -> X509SanDns
                STRING_X509_SAN_URI -> X509SanUri
                STRING_ENTITY_ID -> EntityId
                STRING_DID -> Did
                STRING_VERIFIER_ATTESTATION -> VerifierAttestation
                else -> if (clientId.contains(":")) Other(clientId) else PreRegistered
            }
        }

        /**
         * This value represents the RFC6749 default behavior, i.e., the Client Identifier needs to be known to the
         * Wallet in advance of the Authorization Request. The Verifier metadata is obtained using RFC7591 or through
         * out-of-band mechanisms.
         */
        object PreRegistered : ClientIdScheme(STRING_PRE_REGISTERED)

        /**
         * This value indicates that the Verifier's Redirect URI (or Response URI when Response Mode `direct_post` is
         * used) is also the value of the Client Identifier. The Authorization Request MUST NOT be signed.
         * The Verifier MAY omit the `redirect_uri` Authorization Request parameter (or `response_uri` when Response
         * Mode `direct_post` is used). All Verifier metadata parameters MUST be passed using the `client_metadata`
         * parameter.
         */
        object RedirectUri : ClientIdScheme(STRING_REDIRECT_URI)

        /**
         * When the Client Identifier Scheme is x509_san_dns, the Client Identifier MUST be a DNS name and match a
         * `dNSName` Subject Alternative Name (SAN) [RFC5280](https://www.rfc-editor.org/info/rfc5280) entry in the leaf
         * certificate passed with the request. The request MUST be signed with the private key corresponding to the
         * public key in the leaf X.509 certificate of the certificate chain added to the request in the `x5c` JOSE
         * header [RFC7515](https://www.rfc-editor.org/info/rfc7515) of the signed request object.
         *
         * The Wallet MUST validate the signature and the trust chain of the X.509 certificate.
         * All Verifier metadata other than the public key MUST be obtained from the `client_metadata` parameter.
         * If the Wallet can establish trust in the Client Identifier authenticated through the certificate, e.g.
         * because the Client Identifier is contained in a list of trusted Client Identifiers, it may allow the client
         * to freely choose the `redirect_uri` value. If not, the FQDN of the `redirect_uri` value MUST match the
         * Client Identifier.
         */
        object X509SanDns : ClientIdScheme(STRING_X509_SAN_DNS)

        /**
         * When the Client Identifier Scheme is `x509_san_uri`, the Client Identifier MUST be a URI and match a
         * `uniformResourceIdentifier` Subject Alternative Name (SAN) RFC5280 entry in the leaf certificate passed with
         * the request. The request MUST be signed with the private key corresponding to the public key in the leaf
         * X.509 certificate of the certificate chain added to the request in the `x5c` JOSE header RFC7515 of the
         * signed request object. The Wallet MUST validate the signature and the trust chain of the X.509 certificate.
         * All Verifier metadata other than the public key MUST be obtained from the `client_metadata` parameter. If
         * the Wallet can establish trust in the Client Identifier authenticated through the certificate, e.g. because
         * the Client Identifier is contained in a list of trusted Client Identifiers, it may allow the client to
         * freely choose the `redirect_uri` value. If not, the `redirect_uri` value MUST match the Client Identifier.
         */
        object X509SanUri : ClientIdScheme(STRING_X509_SAN_URI)

        /**
         * This value indicates that the Client Identifier is an Entity Identifier defined in OpenID Connect Federation.
         * Processing rules given in OpenID.Federation MUST be followed. Automatic Registration as defined in
         * OpenID.Federation MUST be used. The Authorization Request MAY also contain a `trust_chain` parameter.
         * The Wallet MUST obtain Verifier metadata only from the Entity Statement(s). The `client_metadata` or
         * `client_metadata_uri` parameter MUST NOT be present in the Authorization Request when this Client
         * Identifier scheme is used.
         */
        object EntityId : ClientIdScheme(STRING_ENTITY_ID)

        /**
         * This value indicates that the Client Identifier is a DID defined in DID-Core. The request MUST be signed
         * with a private key associated with the DID. A public key to verify the signature MUST be obtained from the
         * `verificationMethod` property of a DID Document. Since DID Document may include multiple public keys, a
         * particular public key used to sign the request in question MUST be identified by the `kid` in the JOSE
         * Header. To obtain the DID Document, the Wallet MUST use DID Resolution defined by the DID method used by
         * the Verifier. All Verifier metadata other than the public key MUST be obtained from the `client_metadata`
         * or the `client_metadata_uri` parameter.
         */
        object Did : ClientIdScheme(STRING_DID)

        /**
         * This Client Identifier Scheme allows the Verifier to authenticate using a JWT that is bound to a certain
         * public key. When the Client Identifier Scheme is `verifier_attestation`, the Client Identifier MUST equal
         * the `sub` claim value in the Verifier attestation JWT. The request MUST be signed with the private key
         * corresponding to the public key in the `cnf` claim in the Verifier attestation JWT. This serves as proof of
         * possession of this key. The Verifier attestation JWT MUST be added to the `jwt` JOSE Header of the request
         * object. The Wallet MUST validate the signature on the Verifier attestation JWT. The `iss` claim value of the
         * Verifier Attestation JWT MUST identify a party the Wallet trusts for issuing Verifier Attestation JWTs.
         * If the Wallet cannot establish trust, it MUST refuse the request. If the issuer of the Verifier Attestation
         * JWT adds a `redirect_uris` claim to the attestation, the Wallet MUST ensure the `redirect_uri` request
         * parameter value exactly matches one of the `redirect_uris` claim entries. All Verifier metadata other than
         * the public key MUST be obtained from the `client_metadata` parameter.
         */
        object VerifierAttestation : ClientIdScheme(STRING_VERIFIER_ATTESTATION)

        /**
         * Any not natively supported client id scheme, so it can still be parsed
         */
        class Other(stringRepresentation: String) : ClientIdScheme(stringRepresentation)

        object Serializer : KSerializer<ClientIdScheme> {
            override val descriptor = PrimitiveSerialDescriptor("ClientIdScheme", PrimitiveKind.STRING)

            override fun deserialize(decoder: Decoder): ClientIdScheme = when (val string = decoder.decodeString()) {
                STRING_PRE_REGISTERED -> PreRegistered
                STRING_REDIRECT_URI -> RedirectUri
                STRING_X509_SAN_DNS -> X509SanDns
                STRING_X509_SAN_URI -> X509SanUri
                STRING_ENTITY_ID -> EntityId
                STRING_DID -> Did
                STRING_VERIFIER_ATTESTATION -> VerifierAttestation
                else -> Other(string)
            }

            override fun serialize(encoder: Encoder, value: ClientIdScheme) {
                encoder.encodeString(value.stringRepresentation)
            }
        }
    }

    @Serializable(with = ResponseMode.Serializer::class)
    sealed class ResponseMode(val stringRepresentation: String) {
        override fun toString(): String = this::class.simpleName + "(" + stringRepresentation + ")"

        override fun hashCode() = stringRepresentation.hashCode()

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ResponseMode) return false
            return other.stringRepresentation == stringRepresentation
        }

        companion object {
            private const val STRING_DIRECT_POST = "direct_post"
            private const val STRING_DIRECT_POST_JWT = "direct_post.jwt"
            private const val STRING_QUERY = "query"
            private const val STRING_FRAGMENT = "fragment"
            private const val STRING_DC_API = "dc_api"
            private const val STRING_DC_API_JWT = "dc_api.jwt"
        }

        /**
         * OID4VP: In this mode, the Authorization Response is sent to the Verifier using an HTTPS POST request to an
         * endpoint controlled by the Verifier. The Authorization Response parameters are encoded in the body using the
         * `application/x-www-form-urlencoded` content type. The flow can end with an HTTPS POST request from the Wallet
         * to the Verifier, or it can end with a redirect that follows the HTTPS POST request, if the Verifier responds
         * with a redirect URI to the Wallet.
         */
        object DirectPost : ResponseMode(STRING_DIRECT_POST)

        /**
         * OID4VP: The Response Mode `direct_post.jwt` causes the Wallet to send the Authorization Response using an
         * HTTPS POST request instead of redirecting back to the Verifier. The Wallet adds the response parameter
         * containing the JWT as defined in Section 4.1. of JARM and Section 6.3 in the body of an HTTPS POST request
         * using the `application/x-www-form-urlencoded` content type.
         */
        object DirectPostJwt : ResponseMode(STRING_DIRECT_POST_JWT)

        /**
         * OAuth 2.0: In this mode, Authorization Response parameters are encoded in the query string added to the
         * `redirect_uri` when redirecting back to the Client.
         */
        object Query : ResponseMode(STRING_QUERY)

        /**
         * OAuth 2.0: In this mode, Authorization Response parameters are encoded in the fragment added to the
         * `redirect_uri` when redirecting back to the Client.
         */
        object Fragment : ResponseMode(STRING_FRAGMENT)

        /**
         * The value of the response_mode parameter MUST be dc_api when the response is not encrypted.
         * The Response Mode dc_api causes the Wallet to send the Authorization Response via the DC API.
         */
        object DcApi : ResponseMode(STRING_DC_API)

        /**
         * The value of the response_mode parameter MUST be dc_api.jwt when the response is encrypted.
         * For Response Mode dc_api.jwt, the Wallet includes the response parameter, which contains an
         * encrypted JWT encapsulating the Authorization Response, as defined in Section 8.3.
         */
        object DcApiJwt : ResponseMode(STRING_DC_API_JWT)

        /**
         * Any not natively supported Client ID Scheme, so it can still be parsed
         */
        class Other(stringRepresentation: String) : ResponseMode(stringRepresentation)

        object Serializer : KSerializer<ResponseMode> {
            override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("ResponseMode", PrimitiveKind.STRING)
            override fun deserialize(decoder: Decoder): ResponseMode = when (val string = decoder.decodeString()) {
                STRING_DIRECT_POST -> DirectPost
                STRING_DIRECT_POST_JWT -> DirectPostJwt
                STRING_QUERY -> Query
                STRING_FRAGMENT -> Fragment
                STRING_DC_API -> DcApi
                STRING_DC_API_JWT -> DcApiJwt
                else -> Other(string)
            }

            override fun serialize(encoder: Encoder, value: ResponseMode) {
                encoder.encodeString(value.stringRepresentation)
            }
        }
    }

    /**
     * Error codes for OAuth2 responses
     */
    object Errors {
        /** Invalid (or already used) authorization code: `invalid_code`.*/
        const val INVALID_CODE = "invalid_code"

        /** Invalid access token: `invalid_token`. */
        const val INVALID_TOKEN = "invalid_token"

        /** Invalid DPoP proof (RFC 9449): `invalid_dpop_proof`.*/
        const val INVALID_DPOP_PROOF = "invalid_dpop_proof"

        /** Invalid request in general: `invalid_request`. */
        const val INVALID_REQUEST = "invalid_request"

        /** Invalid client, e.g. missing client authentication: `invalid_client`. */
        const val INVALID_CLIENT = "invalid_client"

        /** The requested scope is invalid, unknown, or malformed: `invalid_scope`. */
        const val INVALID_SCOPE = "invalid_scope"

        /** Invalid grant: `invalid_grant`. */
        const val INVALID_GRANT = "invalid_grant"

        /** OpenID4VP: Wallet did not have requested credentials: `access_denied */
        const val ACCESS_DENIED = "access_denied"

        /** Invalid proofs in OpenID4VCI: `invalid_proof`. */
        const val INVALID_PROOF = "invalid_proof"

        /** RFC9396 Invalid Authorization Details */
        const val INVALID_AUTHDETAILS = "invalid_authorization_details"

        /** Unsupported credential type in OpenID4VCI: `unsupported_credential_type`. */
        const val UNSUPPORTED_CREDENTIAL_TYPE = "unsupported_credential_type"

        /** Credential request denied in OpenID4VCI: `credential_request_denied`. */
        const val CREDENTIAL_REQUEST_DENIED = "credential_request_denied"

        /** Invalid client nonce in OpenID4VCI: `invalid_nonce`. */
        const val INVALID_NONCE = "invalid_nonce"

        /** SIOPv2: End-User cancelled the Authorization Request from the RP. */
        const val USER_CANCELLED = "user_cancelled"

        /** SIOPv2: Self-Issued OP does not support some Relying Party parameter values received in the request. */
        const val REGISTRATION_VALUE_NOT_SUPPORTED = "registration_value_not_supported"

    }

}
