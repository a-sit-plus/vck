package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_DPOP_PROOF
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_TOKEN
import at.asitplus.openid.OpenIdConstants.TOKEN_PREFIX_BEARER
import at.asitplus.openid.OpenIdConstants.TOKEN_PREFIX_DPOP
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.*
import at.asitplus.wallet.lib.oidvci.*
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.datetime.Clock.System
import kotlin.String
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes


/**
 * Simple Bearer token and DPoP token implementation for an OAuth 2.0 authorization server.
 *
 * Implemented from
 * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 */
class TokenService(
    /** Used to create and verify nonces for tokens during issuing. */
    private val nonceService: NonceService = DefaultNonceService(),
    /** Used as issuer for issued DPoP tokens. */
    val publicContext: String = "https://wallet.a-sit.at/authorization-server",
    /** Used to verify client attestation JWTs */
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
    /** Enforce DPoP (RFC 9449), as defined in OpenID4VC HAIP, when all clients implement it */
    private val enforceDpop: Boolean = false,
    /** Used to sign DPoP (RFC 9449) access tokens, if supported by the client */
    private val jwsService: JwsService = DefaultJwsService(DefaultCryptoService(EphemeralKeyWithoutCert())),
    /** Clock used to verify timestamps in access tokens and refresh tokens. */
    private val clock: Clock = System,
    /** Time leeway for verification of timestamps in access tokens and refresh tokens. */
    private val timeLeeway: Duration = 5.minutes,
)  {

    suspend fun buildToken(
        dpop: String?,
        requestUrl: String?,
        requestMethod: HttpMethod?,
    ): TokenResponseParameters =
        if (dpop != null) {
            val clientKey = validateDpopJwtForToken(dpop, requestUrl, requestMethod)
            TokenResponseParameters(
                tokenType = TOKEN_TYPE_DPOP,
                accessToken = jwsService.createSignedJwsAddingParams(
                    header = JwsHeader(
                        algorithm = jwsService.algorithm,
                        type = JwsContentTypeConstants.AT_JWT
                    ),
                    payload = JsonWebToken(
                        issuer = publicContext,
                        jwtId = nonceService.provideNonce(),
                        notBefore = clock.now(),
                        expiration = clock.now().plus(5.minutes),
                        confirmationClaim = ConfirmationClaim(
                            jsonWebKeyThumbprint = clientKey.jwkThumbprintPlain
                        ),
                    ),
                    serializer = JsonWebToken.serializer(),
                    addKeyId = false,
                    addJsonWebKey = true,
                    addX5c = false,
                ).getOrThrow().serialize()
            )
        } else if (enforceDpop == true) {
            Napier.w("dpop: no JWT provided, but enforced")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "no DPoP header value")
        } else {
            TokenResponseParameters(
                tokenType = TOKEN_TYPE_BEARER,
                accessToken = nonceService.provideNonce(),
            )
        }

    suspend fun validateToken(
        authorizationHeader: String,
        dpopHeader: String?,
        requestUrl: String?,
        requestMethod: HttpMethod?,
    ): String = if (authorizationHeader.startsWith(TOKEN_TYPE_BEARER, ignoreCase = true)) {
        val bearerToken = authorizationHeader.removePrefix(TOKEN_PREFIX_BEARER).split(" ").last()
        if (!nonceService.verifyNonce(bearerToken)) { // when to remove them?
            Napier.w("validateToken: Nonce not known: $bearerToken")
            throw OAuth2Exception(INVALID_TOKEN, "access token not valid: $bearerToken")
        }
        bearerToken
    } else if (authorizationHeader.startsWith(TOKEN_TYPE_DPOP, ignoreCase = true)) {
        val dpopToken = authorizationHeader.removePrefix(TOKEN_PREFIX_DPOP).split(" ").last()
        val dpopTokenJwt = validateDpopToken(dpopToken)
        validateDpopJwt(dpopHeader, dpopToken, dpopTokenJwt, requestUrl, requestMethod)
        dpopToken
    } else {
        throw OAuth2Exception(INVALID_TOKEN, "authorization header not valid: $authorizationHeader")
    }

    private fun validateDpopJwtForToken(
        dpop: String,
        requestUrl: String? = null,
        requestMethod: HttpMethod? = null,
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

    private fun validateDpopJwt(
        dpopHeader: String?,
        dpopToken: String,
        dpopTokenJwt: JwsSigned<JsonWebToken>,
        requestUrl: String?,
        requestMethod: HttpMethod?,
    ) {
        val ath = dpopToken.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
        if (dpopHeader.isNullOrEmpty()) {
            Napier.w("validateDpopJwt: No dpop proof in header")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "no dpop proof")
        }
        val jwt = parseAndValidate(dpopHeader)
        if (dpopTokenJwt.payload.confirmationClaim == null ||
            jwt.header.jsonWebKey == null ||
            jwt.header.jsonWebKey!!.jwkThumbprintPlain != dpopTokenJwt.payload.confirmationClaim!!.jsonWebKeyThumbprint
        ) {
            Napier.w("validateDpopJwt: jwk not matching cnf.jkt")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "DPoP JWT JWK not matching cnf.jkt")
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
        if (!jwt.payload.accessTokenHash.equals(ath)) {
            Napier.w("validateDpopJwt: ath expected $ath, was ${jwt.payload.accessTokenHash}")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "DPoP JWT ath not correct")
        }
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

    private suspend fun validateDpopToken(
        dpopToken: String,
    ): JwsSigned<JsonWebToken> {
        val jwt = JwsSigned
            .deserialize<JsonWebToken>(JsonWebToken.serializer(), dpopToken, vckJsonSerializer)
            .getOrElse {
                Napier.w("validateDpopToken: could not parse DPoP Token", it)
                throw OAuth2Exception(INVALID_TOKEN, "could not parse DPoP Token", it)
            }
        if (!verifierJwsService.verifyJws(jwt, jwsService.keyMaterial.jsonWebKey)) {
            Napier.w("validateDpopToken: DPoP not verified")
            throw OAuth2Exception(INVALID_TOKEN, "DPoP Token not verified")
        }
        if (jwt.header.type != JwsContentTypeConstants.AT_JWT) {
            Napier.w("validateDpopToken: typ unexpected: ${jwt.header.type}")
            throw OAuth2Exception(INVALID_TOKEN, "typ not valid: ${jwt.header.type}")
        }
        if (jwt.payload.jwtId == null || !nonceService.verifyNonce(jwt.payload.jwtId!!)) {
            Napier.w("validateDpopToken: jti not known: ${jwt.payload.jwtId}")
            throw OAuth2Exception(INVALID_TOKEN, "jti not valid: ${jwt.payload.jwtId}")
        }
        if (jwt.payload.notBefore == null || jwt.payload.notBefore!! > (clock.now() + timeLeeway)) {
            Napier.w("validateDpopToken: nbf not valid: ${jwt.payload.notBefore}")
            throw OAuth2Exception(INVALID_TOKEN, "nbf not valid: ${jwt.payload.notBefore}")
        }
        if (jwt.payload.expiration == null || jwt.payload.expiration!! < (clock.now() - timeLeeway)) {
            Napier.w("validateDpopToken: exp not valid: ${jwt.payload.expiration}")
            throw OAuth2Exception(INVALID_TOKEN, "exp not valid: ${jwt.payload.expiration}")
        }
        if (jwt.payload.confirmationClaim == null) {
            Napier.w("validateDpopToken: no confirmation claim: $jwt")
            throw OAuth2Exception(INVALID_TOKEN, "no confirmation claim")
        }
        return jwt
    }

    private val JsonWebKey.jwkThumbprintPlain
        get() = this.jwkThumbprint.removePrefix("urn:ietf:params:oauth:jwk-thumbprint:sha256:")

}
