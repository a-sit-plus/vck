package at.asitplus.wallet.lib.oidvci

import at.asitplus.catching
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.SupportedCredentialFormatIsoMdoc
import at.asitplus.openid.SupportedCredentialFormatSdJwt
import at.asitplus.openid.SupportedCredentialFormatW3cVcJsonLd
import at.asitplus.openid.SupportedCredentialFormatW3cVcJwt
import at.asitplus.openid.SupportedCredentialFormatW3cVcJwtJsonLd
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import com.benasher44.uuid.uuid4
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

val OidvciProofsTest by matrixSuite {
    fixture {
        object {
            val authorizationService = SimpleAuthorizationService(
                requirePushedAuthorizationRequests = false,
                strategy = CredentialAuthorizationServiceStrategy(AttributeIndex.schemeSet),
            )
            val oauth2Client = OAuth2Client()
            var issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = AttributeIndex.schemeSet,
            )
            val state = uuid4().toString()

            suspend fun getToken(scope: String): TokenResponseParameters {
                val authnRequest = oauth2Client.createAuthRequestJar(
                    state = state,
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer
                )
                val input = authnRequest as RequestParameters
                val authnResponse = authorizationService.authorize(input) {
                    catching {
                        OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()
                    }
                }.getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                val code = authnResponse.params?.code.shouldNotBeNull()
                val tokenRequest = oauth2Client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer
                )
                return authorizationService.token(tokenRequest, null).getOrThrow()
            }

            var client = WalletService()
        }
    } - {
        test("Do not send any proof when Issuer doesn't support any types") {
            val requestOptions = WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            )
            // this is the important line!
            val metadataWithoutProofs = it.issuer.metadata.withEmptySupportedProofs()
            val credentialFormat =
                it.client.selectSupportedCredentialFormat(requestOptions, metadataWithoutProofs)
                    .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            it.client.createCredential(
                tokenResponse = token,
                metadata = metadataWithoutProofs,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce
            ).getOrThrow().forEach { request ->
                request.shouldBeInstanceOf<WalletService.CredentialRequest.Plain>().apply {
                    this.request.proofs.shouldBeNull()
                }
            }
        }

        test("Do send a proof when Issuer supports a type") {
            val requestOptions = WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            )
            val credentialFormat =
                it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                    .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce
            ).getOrThrow().forEach { request ->
                request.shouldBeInstanceOf<WalletService.CredentialRequest.Plain>().apply {
                    this.request.proofs.shouldNotBeNull()
                }
                /** Validation of the flow with correct proof happens in [OidvciCodeFlowTest] and others */
            }
        }
    }
}

private fun IssuerMetadata.withEmptySupportedProofs(): IssuerMetadata = copy(
    supportedCredentialConfigurations = supportedCredentialConfigurations!!.mapValues {
        when (val format = it.value) {
            is SupportedCredentialFormatIsoMdoc -> format.copy(supportedProofTypes = emptyMap())
            is SupportedCredentialFormatSdJwt -> format.copy(supportedProofTypes = emptyMap())
            is SupportedCredentialFormatW3cVcJsonLd -> format.copy(supportedProofTypes = emptyMap())
            is SupportedCredentialFormatW3cVcJwt -> format.copy(supportedProofTypes = emptyMap())
            is SupportedCredentialFormatW3cVcJwtJsonLd -> format.copy(supportedProofTypes = emptyMap())
        }
    }.toMap()
)