package at.asitplus.wallet.lib.oidc

object OpenIdConstants {

    const val ID_TOKEN = "id_token"

    const val VP_TOKEN = "vp_token"

    const val GRANT_TYPE_CODE = "code"

    const val TOKEN_PREFIX_BEARER = "Bearer "

    const val TOKEN_TYPE_BEARER = "bearer"

    const val URN_TYPE_JWK_THUMBPRINT = "urn:ietf:params:oauth:jwk-thumbprint"

    const val PATH_WELL_KNOWN_CREDENTIAL_ISSUER = "/.well-known/openid-credential-issuer"

    /**
     * To be used in [at.asitplus.wallet.lib.oidvci.AuthorizationDetails.type]
     */
    const val CREDENTIAL_TYPE_OPENID = "openid_credential"

    object ProofTypes {

        /**
         * Proof type in [at.asitplus.wallet.lib.oidvci.CredentialRequestProof]
         */
        const val JWT = "jwt"

        const val JWT_HEADER_TYPE = "openid4vci-proof+jwt"
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
