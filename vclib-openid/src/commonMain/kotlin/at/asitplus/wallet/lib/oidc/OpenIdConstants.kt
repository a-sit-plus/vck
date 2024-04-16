package at.asitplus.wallet.lib.oidc

object OpenIdConstants {

    const val ID_TOKEN = "id_token"

    const val VP_TOKEN = "vp_token"

    const val GRANT_TYPE_CODE = "code"

    const val GRANT_TYPE_PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

    const val TOKEN_PREFIX_BEARER = "Bearer "

    const val TOKEN_TYPE_BEARER = "bearer"

    const val URN_TYPE_JWK_THUMBPRINT = "urn:ietf:params:oauth:jwk-thumbprint"

    const val BINDING_METHOD_COSE_KEY = "cose_key"

    const val PREFIX_DID_KEY = "did:key"

    const val PATH_WELL_KNOWN_CREDENTIAL_ISSUER = "/.well-known/openid-credential-issuer"

    const val SCOPE_OPENID = "openid"

    const val SCOPE_PROFILE = "profile"

    const val CODE_CHALLENGE_METHOD_SHA256 = "S256"

    /**
     * To be used in [at.asitplus.wallet.lib.oidvci.AuthorizationDetails.type]
     */
    const val CREDENTIAL_TYPE_OPENID = "openid_credential"

    object ProofTypes {

        /**
         * Proof type in [at.asitplus.wallet.lib.oidvci.CredentialRequestProof]
         */
        const val JWT = "jwt"

        /**
         * Proof type in [at.asitplus.wallet.lib.oidvci.CredentialRequestProof]
         */
        const val CWT = "cwt"

        const val JWT_HEADER_TYPE = "openid4vci-proof+jwt"
    }

    /**
     * Constants from OID4VP
     */
    object ClientIdSchemes {
        /**
         *  This value represents the RFC6749 default behavior, i.e., the Client Identifier needs to be known to the
         *  Wallet in advance of the Authorization Request. The Verifier metadata is obtained using RFC7591 or
         *  through out-of-band mechanisms.
         */
        const val PRE_REGISTERED = "pre-registered"

        /**
         * This value indicates that the Verifier's redirect URI is also the value of the Client Identifier.
         * In this case, the Authorization Request MUST NOT be signed, the Verifier MAY omit the `redirect_uri`
         * Authorization Request parameter, and all Verifier metadata parameters MUST be passed using the
         * `client_metadata` or `client_metadata_uri` parameter.
         */
        const val REDIRECT_URI = "redirect_uri"

        /**
         * This value indicates that the Client Identifier is an Entity Identifier defined in OpenID Connect Federation.
         * Processing rules given in OpenID.Federation MUST be followed. Automatic Registration as defined in
         * OpenID.Federation MUST be used. The Authorization Request MAY also contain a `trust_chain` parameter.
         * The Wallet MUST obtain Verifier metadata only from the Entity Statement(s). The `client_metadata` or
         * `client_metadata_uri` parameter MUST NOT be present in the Authorization Request when this Client
         * Identifier scheme is used.
         */
        const val ENTITY_ID = "entity_id"

        /**
         * This value indicates that the Client Identifier is a DID defined in DID-Core. The request MUST be signed
         * with a private key associated with the DID. A public key to verify the signature MUST be obtained from the
         * `verificationMethod` property of a DID Document. Since DID Document may include multiple public keys, a
         * particular public key used to sign the request in question MUST be identified by the `kid` in the JOSE
         * Header. To obtain the DID Document, the Wallet MUST use DID Resolution defined by the DID method used by
         * the Verifier. All Verifier metadata other than the public key MUST be obtained from the `client_metadata`
         * or the `client_metadata_uri` parameter.
         */
        const val DID = "did"

        /**
         * This scheme allows the Verifier to authenticate using a JWT that is bound to a certain public key. When the
         * scheme is `verifier_attestation`, the Client Identifier MUST equal the `sub` claim value in the Verifier
         * attestation JWT. The request MUST be signed with the private key corresponding to the public key in the `cnf`
         * claim in the Verifier attestation JWT. This serves as proof of possession of this key. The Verifier
         * attestation JWT MUST be added to the `jwt` JOSE Header of the request object. The Wallet MUST validate the
         * signature on the Verifier attestation JWT. The `iss` claim value of the Verifier Attestation JWT MUST
         * identify a party the Wallet trusts for issuing Verifier Attestation JWTs. If the Wallet cannot establish
         * trust, it MUST refuse the request. If the issuer of the Verifier Attestation JWT adds a `redirect_uris` claim
         * to the attestation, the Wallet MUST ensure the `redirect_uri` request parameter value exactly matches one of
         * the `redirect_uris` claim entries. All Verifier metadata other than the public key MUST be obtained from the
         * `client_metadata` or the `client_metadata_uri parameter`.
         */
        const val VERIFIER_ATTESTATION = "verifier_attestation"
    }

    object ResponseModes {
        /**
         * OID4VP: In this mode, the Authorization Response is sent to the Verifier using an HTTPS POST request to an
         * endpoint controlled by the Verifier. The Authorization Response parameters are encoded in the body using the
         * `application/x-www-form-urlencoded` content type. The flow can end with an HTTPS POST request from the Wallet
         * to the Verifier, or it can end with a redirect that follows the HTTPS POST request, if the Verifier responds
         * with a redirect URI to the Wallet.
         */
        const val DIRECT_POST = "direct_post"

        /**
         * OID4VP: The Response Mode `direct_post.jwt` causes the Wallet to send the Authorization Response using an
         * HTTPS POST request instead of redirecting back to the Verifier. The Wallet adds the response parameter
         * containing the JWT as defined in Section 4.1. of JARM and Section 6.3 in the body of an HTTPS POST request
         * using the `application/x-www-form-urlencoded` content type.
         */
        const val DIRECT_POST_JWT = "direct_post.jwt"

        /**
         * OAuth 2.0: In this mode, Authorization Response parameters are encoded in the query string added to the
         * `redirect_uri` when redirecting back to the Client.
         */
        const val QUERY = "query"

        /**
         * OAuth 2.0: In this mode, Authorization Response parameters are encoded in the fragment added to the
         * `redirect_uri` when redirecting back to the Client.
         */
        const val FRAGMENT = "fragment"
    }

    /**
     * Error codes for OAuth2 responses
     */
    object Errors {
        /**
         * Invalid (or already used) authorization code: `invalid_code`
         */
        const val INVALID_CODE = "invalid_code"

        /**
         * Invalid access token: `invalid_token`
         */
        const val INVALID_TOKEN = "invalid_token"

        /**
         * Invalid request in general: `invalid_request`
         */
        const val INVALID_REQUEST = "invalid_request"

        /**
         * Invalid grant: `invalid_grant`
         */
        const val INVALID_GRANT = "invalid_grant"

        /**
         * Invalid or missing proofs in OpenId4VCI: `invalid_or_missing_proof`
         */
        const val INVALID_PROOF = "invalid_or_missing_proof"

        /**
         * OIDC SIOPv2: End-User cancelled the Authorization Request from the RP.
         */
        const val USER_CANCELLED = "user_cancelled"

        /**
         * OIDC SIOPv2: Self-Issued OP does not support some Relying Party parameter values received in the request.
         */
        const val REGISTRATION_VALUE_NOT_SUPPORTED = "registration_value_not_supported"

        /**
         * OIDC SIOPv2: Self-Issued OP does not support any of the Subject Syntax Types supported by the RP, which were
         * communicated in the request in the `subject_syntax_types_supported` parameter.
         */
        const val SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED = "subject_syntax_types_not_supported"

        /**
         * OIDC SIOPv2: the `client_metadata_uri` in the Self-Issued OpenID Provider request returns an error or
         * contains invalid data.
         */
        const val INVALID_REGISTRATION_URI = "invalid_registration_uri"

        /**
         * OIDC SIOPv2: the `client_metadata` parameter contains an invalid RP parameter Object.
         */
        const val INVALID_REGISTRATION_OBJECT = "invalid_registration_object"
    }

}
