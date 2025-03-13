package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_DPOP_PROOF
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.*
import at.asitplus.wallet.lib.oidvci.*
import io.github.aakira.napier.Napier
import io.ktor.http.*
import kotlinx.datetime.Clock
import kotlinx.datetime.Clock.System
import kotlin.String
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

interface TokenGenerationService {
    suspend fun buildToken(
        dpop: String?,
        requestUrl: String?,
        requestMethod: HttpMethod?,
        oidcUserInfo: OidcUserInfoExtended?,
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
        dpop: String?,
        requestUrl: String?,
        requestMethod: HttpMethod?,
        oidcUserInfo: OidcUserInfoExtended?,
        authorizationDetails: Set<AuthorizationDetails>?,
        scope: String?,
    ): TokenResponseParameters =
        if (dpop == null) {
            Napier.w("dpop: no JWT provided, but enforced")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "no DPoP header value")
        } else {
            val clientKey = validateDpopJwtForToken(dpop, requestUrl, requestMethod)
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
                        userInfo = oidcUserInfo?.jsonObject,
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
                        userInfo = oidcUserInfo?.jsonObject,
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
        dpop: String,
        requestUrl: String?,
        requestMethod: HttpMethod?,
    ): JsonWebKey {
        val jwt = parseAndValidate(dpop)
        if (jwt.header.type != JwsContentTypeConstants.DPOP_JWT) {
            Napier.w("validateDpopJwtForToken: invalid header type ${jwt.header.type} ")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "invalid type")
        }
        // Verify nonce, but where to get it?
        if (jwt.payload.httpTargetUrl != requestUrl) {
            Napier.w("validateDpopJwt: htu ${jwt.payload.httpTargetUrl} not matching requestUrl $requestUrl")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "DPoP JWT htu incorrect")
        }
        if (jwt.payload.httpMethod != requestMethod?.value?.uppercase()) {
            Napier.w("validateDpopJwt: htm ${jwt.payload.httpMethod} not matching requestMethod $requestMethod")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "DPoP JWT htm incorrect")
        }
        val clientKey = jwt.header.jsonWebKey ?: run {
            Napier.w("validateDpopJwtForToken: no client key in $jwt")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "DPoP JWT contains no public key")
        }
        return clientKey
    }

    private fun parseAndValidate(dpopHeader: String): JwsSigned<JsonWebToken> =
        JwsSigned.deserialize(JsonWebToken.serializer(), dpopHeader, vckJsonSerializer)
            .getOrElse {
                Napier.w("parse: could not parse DPoP JWT", it)
                throw OAuth2Exception(INVALID_DPOP_PROOF, "could not parse DPoP JWT", it)
            }.also {
                if (!verifierJwsService.verifyJwsObject(it)) {
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
        dpop: String?,
        requestUrl: String?,
        requestMethod: HttpMethod?,
        oidcUserInfo: OidcUserInfoExtended?,
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
            ValidatedAccessToken(it.accessToken, oidcUserInfo, authorizationDetails, scope)
        )
    }

    fun getValidatedAccessToken(accessToken: String): ValidatedAccessToken? {
        return listOfValidatedAccessToken.firstOrNull { it.token == accessToken }
    }
}
