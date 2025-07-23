package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.*
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.NonceService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidDpopProof
import io.github.aakira.napier.Napier
import kotlin.time.Clock
import kotlin.time.Clock.System
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

/** Strategy to generate access tokens, to use in [SimpleAuthorizationService]. */
interface TokenGenerationService {
    /** Builds an access token, probably with a refresh token. Input parameters are assumed to be validated already. */
    suspend fun buildToken(
        httpRequest: RequestInfo?,
        userInfo: OidcUserInfoExtended?,
        authorizationDetails: Set<AuthorizationDetails>?,
        scope: String?,
    ): TokenResponseParameters
}

/**
 * Simple DPoP token generation for an OAuth 2.0 authorization server, with [OpenId4VciAccessToken] as payload.
 *
 * Implemented from
 * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 */
class JwtTokenGenerationService(
    /** Used to create nonces for tokens during issuing. */
    internal val nonceService: NonceService = DefaultNonceService(),
    /** Used as issuer for issued DPoP tokens. */
    internal val publicContext: String = "https://wallet.a-sit.at/authorization-server",
    /** Used to verify client attestation JWTs. */
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    /** Used to sign DPoP (RFC 9449) access tokens, if supported by the client. */
    internal val signToken: SignJwtFun<OpenId4VciAccessToken> = SignJwt(EphemeralKeyWithoutCert(), JwsHeaderJwk()),
    /** Clock used to verify timestamps in access tokens and refresh tokens. */
    private val clock: Clock = System,
    /** Whether to issue refresh tokens, which may be used by clients to get a new access token. */
    private val issueRefreshToken: Boolean = false,
) : TokenGenerationService {

    override suspend fun buildToken(
        httpRequest: RequestInfo?,
        userInfo: OidcUserInfoExtended?,
        authorizationDetails: Set<AuthorizationDetails>?,
        scope: String?,
    ): TokenResponseParameters =
        if (httpRequest?.dpop == null) {
            Napier.w("dpop: no JWT provided, but enforced")
            throw InvalidDpopProof("no DPoP header value")
        } else {
            val clientKey = validateDpopJwtForToken(httpRequest)
            TokenResponseParameters(
                expires = 5.minutes,
                tokenType = TOKEN_TYPE_DPOP,
                refreshToken = if (issueRefreshToken) signToken(
                    JwsContentTypeConstants.RT_JWT,
                    OpenId4VciAccessToken(
                        issuer = publicContext,
                        jwtId = nonceService.provideNonce(),
                        notBefore = clock.now(),
                        expiration = clock.now().plus(30.days),
                        confirmationClaim = ConfirmationClaim(
                            jsonWebKeyThumbprint = clientKey.jwkThumbprintPlain
                        ),
                        userInfo = userInfo?.jsonObject,
                        scope = scope,
                        authorizationDetails = authorizationDetails,
                    ),
                    OpenId4VciAccessToken.serializer(),
                ).getOrThrow().serialize() else null,
                accessToken = signToken(
                    JwsContentTypeConstants.OID4VCI_AT_JWT,
                    OpenId4VciAccessToken(
                        issuer = publicContext,
                        jwtId = nonceService.provideNonce(),
                        notBefore = clock.now(),
                        expiration = clock.now().plus(5.minutes),
                        confirmationClaim = ConfirmationClaim(
                            jsonWebKeyThumbprint = clientKey.jwkThumbprintPlain
                        ),
                        userInfo = userInfo?.jsonObject,
                        scope = scope,
                        authorizationDetails = authorizationDetails,
                    ),
                    OpenId4VciAccessToken.serializer(),
                ).getOrThrow().serialize(),
                authorizationDetails = authorizationDetails,
                scope = scope,
            )
        }

    private suspend fun validateDpopJwtForToken(
        httpRequest: RequestInfo,
    ): JsonWebKey {
        val jwt = httpRequest.dpop?.parseAndValidate()
            ?: throw InvalidDpopProof("no DPoP header value")

        if (jwt.header.type != JwsContentTypeConstants.DPOP_JWT) {
            Napier.w("validateDpopJwtForToken: invalid header type ${jwt.header.type} ")
            throw InvalidDpopProof("invalid type")
        }
        // Verify nonce, but where to get it?
        if (jwt.payload.httpTargetUrl != httpRequest.url) {
            Napier.w("validateDpopJwt: htu ${jwt.payload.httpTargetUrl} not matching requestUrl ${httpRequest.url}")
            throw InvalidDpopProof("DPoP JWT htu incorrect")
        }
        if (jwt.payload.httpMethod != httpRequest.method.value.uppercase()) {
            Napier.w("validateDpopJwt: htm ${jwt.payload.httpMethod} not matching requestMethod ${httpRequest.method}")
            throw InvalidDpopProof("DPoP JWT htm incorrect")
        }
        val clientKey = jwt.header.jsonWebKey ?: run {
            Napier.w("validateDpopJwtForToken: no client key in $jwt")
            throw InvalidDpopProof("DPoP JWT contains no public key")
        }
        return clientKey
    }

    private suspend fun String.parseAndValidate(): JwsSigned<JsonWebToken> =
        JwsSigned.deserialize(JsonWebToken.serializer(), this, vckJsonSerializer)
            .getOrElse {
                Napier.w("parse: could not parse DPoP JWT", it)
                throw InvalidDpopProof("could not parse DPoP JWT", it)
            }.also {
                if (!verifyJwsObject(it)) {
                    Napier.w("parse: DPoP not verified")
                    throw InvalidDpopProof("DPoP JWT not verified")
                }
            }

    private val JsonWebKey.jwkThumbprintPlain
        get() = this.jwkThumbprint.removePrefix("urn:ietf:params:oauth:jwk-thumbprint:sha256:")

}

/**
 * Simple bearer token generation for an OAuth 2.0 authorization server.
 *
 * Implemented from
 * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 */
class BearerTokenGenerationService(
    /** Used to create nonces for tokens during issuing. */
    internal val nonceService: NonceService = DefaultNonceService(),
) : TokenGenerationService {

    /** Only for local tests. */
    private val listOfValidatedAccessToken = mutableListOf<ValidatedAccessToken>()

    override suspend fun buildToken(
        httpRequest: RequestInfo?,
        userInfo: OidcUserInfoExtended?,
        authorizationDetails: Set<AuthorizationDetails>?,
        scope: String?,
    ): TokenResponseParameters = TokenResponseParameters(
        expires = 5.minutes,
        tokenType = TOKEN_TYPE_BEARER,
        accessToken = nonceService.provideNonce(),
        authorizationDetails = authorizationDetails,
        scope = scope,
    ).also {
        listOfValidatedAccessToken.add(
            ValidatedAccessToken(it.accessToken, userInfo, authorizationDetails, scope)
        )
    }

    fun getValidatedAccessToken(accessToken: String): ValidatedAccessToken? {
        return listOfValidatedAccessToken.firstOrNull { it.token == accessToken }
    }
}
