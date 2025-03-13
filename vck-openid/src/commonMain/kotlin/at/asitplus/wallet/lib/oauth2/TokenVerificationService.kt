package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OpenIdConstants.Errors.INVALID_DPOP_PROOF
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_TOKEN
import at.asitplus.openid.OpenIdConstants.TOKEN_PREFIX_BEARER
import at.asitplus.openid.OpenIdConstants.TOKEN_PREFIX_DPOP
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.*
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
class TokenVerificationService(
    /** Used to verify nonces of tokens. */
    private val nonceService: NonceService,
    /** Used to verify the signature of the DPoP access token. */
    private val issuerKey: JsonWebKey,
    /** Used to verify client attestation JWTs */
    internal val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
    /** Clock used to verify timestamps in access tokens and refresh tokens. */
    private val clock: Clock = System,
    /** Time leeway for verification of timestamps in access tokens and refresh tokens. */
    private val timeLeeway: Duration = 5.minutes,
)  {

    suspend fun validateRefreshToken(
        refreshToken: String,
        dpopHeader: String?,
        requestUrl: String?,
        requestMethod: HttpMethod?,
    ): String {
        val dpopToken = refreshToken.removePrefix(TOKEN_PREFIX_DPOP).split(" ").last()
        val dpopTokenJwt = validateDpopToken(dpopToken, JwsContentTypeConstants.RT_JWT)
        validateDpopJwt(dpopHeader, null, dpopTokenJwt, requestUrl, requestMethod)
        return dpopToken
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
        val dpopTokenJwt = validateDpopToken(dpopToken, JwsContentTypeConstants.AT_JWT)
        validateDpopJwt(dpopHeader, dpopToken, dpopTokenJwt, requestUrl, requestMethod)
        dpopToken
    } else {
        throw OAuth2Exception(INVALID_TOKEN, "authorization header not valid: $authorizationHeader")
    }

    private fun validateDpopJwt(
        dpopHeader: String?,
        dpopToken: String?,
        dpopTokenJwt: JwsSigned<JsonWebToken>,
        requestUrl: String?,
        requestMethod: HttpMethod?,
    ) {
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
        dpopToken?.let {
            val ath = dpopToken.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
            if (!jwt.payload.accessTokenHash.equals(ath)) {
                Napier.w("validateDpopJwt: ath expected $ath, was ${jwt.payload.accessTokenHash}")
                throw OAuth2Exception(INVALID_DPOP_PROOF, "DPoP JWT ath not correct")
            }
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
        expectedType: String,
    ): JwsSigned<JsonWebToken> {
        val jwt = JwsSigned
            .deserialize<JsonWebToken>(JsonWebToken.serializer(), dpopToken, vckJsonSerializer)
            .getOrElse {
                Napier.w("validateDpopToken: could not parse DPoP Token", it)
                throw OAuth2Exception(INVALID_TOKEN, "could not parse DPoP Token", it)
            }
        if (!verifierJwsService.verifyJws(jwt, issuerKey)) {
            Napier.w("validateDpopToken: DPoP not verified")
            throw OAuth2Exception(INVALID_TOKEN, "DPoP Token not verified")
        }
        if (jwt.header.type != expectedType) {
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
