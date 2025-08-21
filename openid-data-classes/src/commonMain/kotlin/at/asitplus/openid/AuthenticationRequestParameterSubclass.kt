package at.asitplus.openid

import at.asitplus.catchingUnwrapped
import at.asitplus.csc.Hashes
import at.asitplus.csc.enums.SignatureQualifier
import at.asitplus.csc.or
import at.asitplus.dif.PresentationDefinition
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.josef.JsonWebToken
import kotlin.time.Instant

sealed class AuthenticationRequestParameterSubclass {
    abstract fun toAuthenticationRequestParameters(): AuthenticationRequestParameters

    data class OidcOAuth2(
        /**
         * OIDC: REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server.
         */
        val clientId: String,

        /**
         * OIDC: REQUIRED. OAuth 2.0 Response Type value that determines the authorization processing flow to be used,
         * including what parameters are returned from the endpoints used. When using the Authorization Code Flow, this
         * value is `code`.
         *
         * For OIDC SIOPv2, this is typically `id_token`. For OID4VP, this is typically `vp_token`.
         */
        val responseType: String,

        /**
         * OIDC: REQUIRED. Redirection URI to which the response will be sent. This URI MUST exactly match one of the
         * Redirection URI values for the Client pre-registered at the OpenID Provider, with the matching performed as
         * described in Section 6.2.1 of RFC3986 (Simple String Comparison).
         *
         * Optional when JAR (RFC9101) is used.
         *
         * See also [redirectUrlExtracted]
         */
        val redirectUrl: String,

        /**
         * OIDC: scope is REQUIRED
         * OID4VP: PresentationDefinition, PresentationDefinitionUrl or scope must be present
         */
        val presentationDefinition: PresentationDefinition? = null,
        val presentationDefinitionUrl: String? = null,
        val scope: String?,

        //Optional paramters
        val walletNonce: String?,
        val claims: AuthnRequestClaims?,
        val clientMetadata: RelyingPartyMetadata?,
        val clientMetadataUri: String?,
        val idTokenHint: String?,
        val requestUriMethod: String?,
        val idTokenType: String?,
        val state: String?,
        val authorizationDetails: List<AuthorizationDetails>?,
        val codeChallenge: String?,
        val codeChallengeMethod: String?,
        val transactionData: List<TransactionDataBase64Url>?,
        val resource: String?,
        val responseMode: OpenIdConstants.ResponseMode?,
        val responseUrl: String?,
        val nonce: String?
    ) : AuthenticationRequestParameterSubclass() {

        init {
            require(presentationDefinition or presentationDefinitionUrl or scope) { "OID4VP: PresentationDefinition, PresentationDefinitionUrl or scope must be present" }
        }

        override fun toAuthenticationRequestParameters() = AuthenticationRequestParameters(
            walletNonce = walletNonce,
            claims = claims,
            clientMetadata = clientMetadata,
            clientMetadataUri = clientMetadataUri,
            idTokenHint = idTokenHint,
            requestUriMethod = requestUriMethod,
            idTokenType = idTokenType,
            presentationDefinition = presentationDefinition,
            presentationDefinitionUrl = presentationDefinitionUrl,
            clientId = clientId,
            responseType = responseType,
            redirectUrl = redirectUrl,
            scope = scope,
            state = state,
            authorizationDetails = authorizationDetails,
            codeChallenge = codeChallenge,
            codeChallengeMethod = codeChallengeMethod,
            transactionData = transactionData,
            resource = resource,
            responseMode = responseMode,
            responseUrl = responseUrl,
            nonce = nonce
        )

        companion object {
            fun AuthenticationRequestParameters.toOidcOAuth2() = catchingUnwrapped {
                OidcOAuth2(
                    walletNonce = walletNonce,
                    claims = claims,
                    clientMetadata = clientMetadata,
                    clientMetadataUri = clientMetadataUri,
                    idTokenHint = idTokenHint,
                    requestUriMethod = requestUriMethod,
                    idTokenType = idTokenType,
                    presentationDefinition = presentationDefinition,
                    presentationDefinitionUrl = presentationDefinitionUrl,
                    clientId = clientId!!,
                    responseType = responseType!!,
                    redirectUrl = redirectUrl!!,
                    scope = scope,
                    state = state,
                    authorizationDetails = authorizationDetails,
                    codeChallenge = codeChallenge,
                    codeChallengeMethod = codeChallengeMethod,
                    transactionData = transactionData,
                    resource = resource,
                    responseMode = responseMode,
                    responseUrl = responseUrl,
                    nonce = nonce
                )
            }
        }
    }

    data class OidcJar(
        val clientId: String,
        val walletNonce: String? = null,
        val claims: AuthnRequestClaims? = null,
        val clientMetadata: RelyingPartyMetadata? = null,
        val clientMetadataUri: String? = null,
        val idTokenHint: String? = null,
        val requestUriMethod: String? = null,
        val idTokenType: String? = null,
        val presentationDefinition: PresentationDefinition? = null,
        val request: String? = null,
        val requestUri: String? = null,
        val transactionData: List<TransactionDataBase64Url>? = null,
        val issuer: String? = null,
        val audience: String? = null,
        val issuedAt: Instant? = null,
        val responseUrl: String? = null,
        val nonce: String? = null,
        val state: String? = null,
    ) : AuthenticationRequestParameterSubclass() {
        override fun toAuthenticationRequestParameters(): AuthenticationRequestParameters {
            TODO("Not yet implemented")
        }
    }

    data class OidcDcApi(
        val test: String
    ) : AuthenticationRequestParameterSubclass() {
        override fun toAuthenticationRequestParameters(): AuthenticationRequestParameters {
            TODO("Not yet implemented")
        }
    }

    data class CscOAuth2(
        val credentialID: ByteArray?,
        val signatureQualifier: SignatureQualifier?,
        val numSignatures: Int?,
        val hashes: Hashes?,
        val hashAlgorithmOid: ObjectIdentifier?,
        val description: String?,
        val accountToken: JsonWebToken?,
        val clientData: String?,
        val clientId: String,
        val responseType: String,
        val scope: String?,
        val state: String?,
        val authorizationDetails: List<AuthorizationDetails>?,
        val codeChallenge: String?,
        val codeChallengeMethod: String?,
        val lang: String?,
        val resource: String?,
        val redirectUrl: String?,
        val responseMode: OpenIdConstants.ResponseMode?
    ) : AuthenticationRequestParameterSubclass() {
        override fun toAuthenticationRequestParameters(): AuthenticationRequestParameters {
            TODO("Not yet implemented")
        }
    }
}