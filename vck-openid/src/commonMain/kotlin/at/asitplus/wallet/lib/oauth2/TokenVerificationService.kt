package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_DPOP_PROOF
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_TOKEN
import at.asitplus.openid.OpenIdConstants.TOKEN_PREFIX_BEARER
import at.asitplus.openid.OpenIdConstants.TOKEN_PREFIX_DPOP
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.oidvci.NonceService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.Companion.InvalidToken
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.datetime.Clock.System
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes


/**
 * Verifies access tokens and refresh tokens, that may have been generated by a [TokenGenerationService],
 * or by any other OAuth 2.0 authorization server.
 */
interface TokenVerificationService {
    suspend fun validateRefreshToken(
        refreshToken: String,
        request: RequestInfo?,
    ): String

    suspend fun validateTokenExtractUser(
        authorizationHeader: String,
        request: RequestInfo?,
    ): ValidatedAccessToken
}

/**
 * Verifies JWT tokens that have been generated by [JwtTokenGenerationService], as [OpenId4VciAccessToken].
 *
 * Implemented from
 * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 */
class JwtTokenVerificationService(
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
) : TokenVerificationService {

    override suspend fun validateRefreshToken(
        refreshToken: String,
        request: RequestInfo?,
    ): String {
        val dpopToken = refreshToken.removePrefix(TOKEN_PREFIX_DPOP).split(" ").last()
        val dpopTokenJwt = validateDpopToken(dpopToken, JwsContentTypeConstants.RT_JWT)
        validateDpopJwt(null, dpopTokenJwt, request)
        return dpopToken
    }

    override suspend fun validateTokenExtractUser(
        authorizationHeader: String,
        request: RequestInfo?,
    ): ValidatedAccessToken = if (authorizationHeader.startsWith(TOKEN_TYPE_DPOP, ignoreCase = true)) {
        val dpopToken = authorizationHeader.removePrefix(TOKEN_PREFIX_DPOP).split(" ").last()
        val dpopTokenJwt = validateDpopToken(dpopToken, JwsContentTypeConstants.OID4VCI_AT_JWT)
        validateDpopJwt(dpopToken, dpopTokenJwt, request)
        with(dpopTokenJwt.payload) {
            ValidatedAccessToken(
                token = dpopToken,
                userInfoExtended = userInfo?.let { OidcUserInfoExtended.fromJsonObject(it) }?.getOrNull(),
                authorizationDetails = authorizationDetails?.filterIsInstance<OpenIdAuthorizationDetails>()?.toSet(),
                scope = scope
            )
        }
    } else {
        throw OAuth2Exception(INVALID_TOKEN, "authorization header not valid: $authorizationHeader")
    }

    private fun validateDpopJwt(
        dpopToken: String?,
        dpopTokenJwt: JwsSigned<OpenId4VciAccessToken>,
        request: RequestInfo?,
    ) {
        if (request?.dpop.isNullOrEmpty()) {
            Napier.w("validateDpopJwt: No dpop proof in header")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "no dpop proof")
        }
        val jwt = parseAndValidate(request.dpop)
        if (dpopTokenJwt.payload.confirmationClaim == null ||
            jwt.header.jsonWebKey == null ||
            jwt.header.jsonWebKey!!.jwkThumbprintPlain != dpopTokenJwt.payload.confirmationClaim!!.jsonWebKeyThumbprint
        ) {
            Napier.w("validateDpopJwt: jwk not matching cnf.jkt")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "DPoP JWT JWK not matching cnf.jkt")
        }
        // Verify nonce, but where to get it?
        if (jwt.payload.httpTargetUrl != request.url) {
            Napier.w("validateDpopJwt: htu ${jwt.payload.httpTargetUrl} not matching requestUrl ${request.url}")
            throw OAuth2Exception(INVALID_DPOP_PROOF, "DPoP JWT htu incorrect")
        }
        if (jwt.payload.httpMethod != request.method?.value?.uppercase()) {
            Napier.w("validateDpopJwt: htm ${jwt.payload.httpMethod} not matching requestMethod ${request.method}")
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
    ): JwsSigned<OpenId4VciAccessToken> {
        val jwt = JwsSigned
            .deserialize<OpenId4VciAccessToken>(OpenId4VciAccessToken.serializer(), dpopToken, vckJsonSerializer)
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

/**
 * Verifies Bearer tokens that have been generated by [BearerTokenGenerationService].
 * This does only work for internal authorization servers, because we could not store the actual user data otherwise.
 */
class BearerTokenVerificationService(
    /** Used to verify nonces of tokens. */
    internal val nonceService: NonceService,
    /** Needs to local token generation service, to load actual user data. */
    internal val tokenGenerationService: BearerTokenGenerationService,
) : TokenVerificationService {

    override suspend fun validateRefreshToken(
        refreshToken: String,
        request: RequestInfo?
    ): String {
        throw InvalidToken("Refresh tokens are not supported by this verifier")
    }

    override suspend fun validateTokenExtractUser(
        authorizationHeader: String,
        request: RequestInfo?
    ): ValidatedAccessToken = if (authorizationHeader.startsWith(TOKEN_TYPE_BEARER, ignoreCase = true)) {
        val token = authorizationHeader.removePrefix(TOKEN_PREFIX_BEARER).split(" ").last()
        if (!nonceService.verifyNonce(token)) { // when to remove them?
            Napier.w("validateToken: Nonce not known: $token")
            throw InvalidToken("access token not valid: $token")
        }
        tokenGenerationService.getValidatedAccessToken(token)
            ?: throw InvalidToken("access token not valid: $token")
    } else {
        throw InvalidToken("authorization header not valid: $authorizationHeader")
    }

}
