package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_DPOP_PROOF
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.*
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.NonceService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlinx.datetime.Clock.System
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
    internal val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
    /** Used to sign DPoP (RFC 9449) access tokens, if supported by the client. */
    internal val jwsService: JwsService = DefaultJwsService(DefaultCryptoService(EphemeralKeyWithoutCert())),
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
            throw OAuth2Exception(INVALID_DPOP_PROOF, "no DPoP header value")
        } else {
            val clientKey = validateDpopJwtForToken(httpRequest)
            TokenResponseParameters(
                expires = 5.minutes,
                tokenType = TOKEN_TYPE_DPOP,
                refreshToken = if (issueRefreshToken) jwsService.createSignedJwsAddingParams(
                    header = JwsHeader(
                        algorithm = jwsService.algorithm,
                        type = JwsContentTypeConstants.RT_JWT
                    ),
                    payload = OpenId4VciAccessToken(
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
                    serializer = OpenId4VciAccessToken.serializer(),
                    addKeyId = false,
                    addJsonWebKey = true,
                    addX5c = false,
                ).getOrThrow().serialize() else null,
                accessToken = jwsService.createSignedJwsAddingParams(
                    header = JwsHeader(
                        algorithm = jwsService.algorithm,
                        type = JwsContentTypeConstants.OID4VCI_AT_JWT
                    ),
                    payload = OpenId4VciAccessToken(
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
                    serializer = OpenId4VciAccessToken.serializer(),
                    addKeyId = false,
                    addJsonWebKey = true,
                    addX5c = false,
                ).getOrThrow().serialize(),
                authorizationDetails = authorizationDetails,
                scope = scope,
            )
        }

    private fun validateDpopJwtForToken(
        httpRequest: RequestInfo,
    ): JsonWebKey {
        val jwt = httpRequest.dpop?.parseAndValidate()
            ?: throw OAuth2Exception(INVALID_DPOP_PROOF, "no DPoP header value")

        if (jwt.header.type != JwsContentTypeConstants.DPOP_JWT) {
            Napier.w("validateDpopJwtForToken: invalid header type ${jwt.header.type} ")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "invalid type")
        }
        // Verify nonce, but where to get it?
        if (jwt.payload.httpTargetUrl != httpRequest.url) {
            Napier.w("validateDpopJwt: htu ${jwt.payload.httpTargetUrl} not matching requestUrl ${httpRequest.url}")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "DPoP JWT htu incorrect")
        }
        if (jwt.payload.httpMethod != httpRequest.method.value.uppercase()) {
            Napier.w("validateDpopJwt: htm ${jwt.payload.httpMethod} not matching requestMethod ${httpRequest.method}")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "DPoP JWT htm incorrect")
        }
        val clientKey = jwt.header.jsonWebKey ?: run {
            Napier.w("validateDpopJwtForToken: no client key in $jwt")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "DPoP JWT contains no public key")
        }
        return clientKey
    }

    private fun String.parseAndValidate(): JwsSigned<JsonWebToken> =
        JwsSigned.deserialize(JsonWebToken.serializer(), this, vckJsonSerializer)
            .getOrElse {
                Napier.w("parse: could not parse DPoP JWT", it)
                throw OAuth2Exception(INVALID_DPOP_PROOF, "could not parse DPoP JWT", it)
            }.also {
                if (!this@JwtTokenGenerationService.verifierJwsService.verifyJwsObject(it)) {
                    Napier.w("parse: DPoP not verified")
                    throw OAuth2Exception(INVALID_DPOP_PROOF, "DPoP JWT not verified")
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
