package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.CredentialOfferGrants
import at.asitplus.openid.CredentialOfferGrantsPreAuthCode
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.SupportedCredentialFormatSdJwt
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondOAuth2Error
import at.asitplus.wallet.lib.oauth2.DPoPNonce
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oidvci.CredentialIdentifierInfo
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OpenId4VciClient
import com.benasher44.uuid.uuid4
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.client.engine.mock.*
import io.ktor.http.*

/**
 * [RFC 9449 9.](https://datatracker.ietf.org/doc/html/rfc9449#section-9): DPoP nonces are only accepted by the server
 * that issued them, so the nonce of the authorization server must not be used for the credential issuer.
 */
val OpenId4VciClientDPoPNonceTest by matrixSuite {

    test("credential request to another origin does not carry the DPoP nonce of the authorization server") {
        val authorizationServer = "https://as.example.com"
        val credentialIssuer = "https://credentials.example.com"
        val authorizationServerNonce = uuid4().toString()
        val format = SupportedCredentialFormatSdJwt(sdJwtVcType = "urn:example:credential", scope = "example")
        // No nonce endpoint, which would supply the DPoP nonce of the credential issuer
        val issuerMetadata = IssuerMetadata(
            credentialIssuer = credentialIssuer,
            authorizationServers = setOf(authorizationServer),
            credentialEndpointUrl = "$credentialIssuer/credential",
            supportedCredentialConfigurations = mapOf("example" to format),
        )
        val oauthMetadata = OAuth2AuthorizationServerMetadata(
            issuer = authorizationServer,
            tokenEndpoint = "$authorizationServer/token",
            dpopSigningAlgValuesSupportedStrings = setOf(JwsAlgorithm.Signature.ES256.identifier),
        )
        val credentialRequestNonces = mutableListOf<String?>()
        val mockEngine = MockEngine { request ->
            when (request.url.toString()) {
                "$authorizationServer/token" -> respond(
                    joseCompliantSerializer.encodeToString(
                        TokenResponseParameters(
                            accessToken = uuid4().toString(),
                            tokenType = TOKEN_TYPE_DPOP,
                            scope = format.scope,
                        )
                    ),
                    headers = headers {
                        append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        append(HttpHeaders.DPoPNonce, authorizationServerNonce)
                    },
                )

                "$credentialIssuer/credential" -> {
                    credentialRequestNonces += request.toRequestInfo().dpop.shouldNotBeNull().payload.nonce
                    // The response does not matter here, only what the client sent
                    respondOAuth2Error(OAuth2Exception.InvalidRequest("stop"))
                }

                else -> respondError(HttpStatusCode.NotFound)
            }
        }
        val client = OpenId4VciKtorClient(
            engine = mockEngine,
            oid4vciService = OpenId4VciClient(),
            oauth2Client = OAuth2KtorClient(
                engine = mockEngine,
                oAuth2Client = OAuth2Client(),
                randomSource = RandomSource.Default,
            ),
        )

        client.loadCredentialWithOfferReturningResult(
            credentialOffer = CredentialOffer(
                credentialIssuer = credentialIssuer,
                configurationIds = setOf("example"),
                grants = CredentialOfferGrants(
                    preAuthorizedCode = CredentialOfferGrantsPreAuthCode(preAuthorizedCode = uuid4().toString())
                ),
            ),
            credentialIdentifierInfo = CredentialIdentifierInfo(issuerMetadata, "example", format),
            authorizationServerMetadata = oauthMetadata,
        ).exceptionOrNull().shouldNotBeNull()

        credentialRequestNonces shouldBe listOf(null)
    }
}
