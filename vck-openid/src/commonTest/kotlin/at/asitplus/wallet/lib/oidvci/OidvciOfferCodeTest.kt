package at.asitplus.wallet.lib.oidvci

import at.asitplus.catching
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.openid.DummyUserProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

val OidvciOfferCodeTest by testSuite {

    withFixtureGenerator {
        object {
            val authorizationService = SimpleAuthorizationService(
                strategy = CredentialAuthorizationServiceStrategy(
                    setOf(
                        AtomicAttribute2023,
                        MobileDrivingLicenceScheme
                    )
                ),
            )
            val issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(AtomicAttribute2023, MobileDrivingLicenceScheme),
            )
            val client = WalletService()
            val oauth2Client = OAuth2Client()
            val state = uuid4().toString()

            suspend fun getToken(
                credentialOffer: CredentialOffer,
                scope: String,
            ): TokenResponseParameters {
                val authnRequest = oauth2Client.createAuthRequestJar(
                    state = state,
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer,
                    issuerState = credentialOffer.grants?.authorizationCode.shouldNotBeNull().issuerState
                )
                val input = authnRequest as RequestParameters
                val authnResponse = authorizationService.authorize(input) { catching { DummyUserProvider.user } }
                    .getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                val code = authnResponse.params?.code
                    .shouldNotBeNull()
                val tokenRequest = oauth2Client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer
                )
                return authorizationService.token(tokenRequest, null).getOrThrow()
            }

            suspend fun getToken(
                credentialOffer: CredentialOffer,
                authorizationDetails: Set<AuthorizationDetails>,
            ): TokenResponseParameters {
                val authnRequest = oauth2Client.createAuthRequestJar(
                    state = state,
                    authorizationDetails = authorizationDetails,
                    issuerState = credentialOffer.grants?.authorizationCode.shouldNotBeNull().issuerState
                )
                val input = authnRequest as RequestParameters
                val authnResponse = authorizationService.authorize(input) { catching { DummyUserProvider.user } }
                    .getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                val code = authnResponse.params?.code
                    .shouldNotBeNull()
                val tokenRequest = oauth2Client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    authorizationDetails = authorizationDetails,
                )
                return authorizationService.token(tokenRequest, null).getOrThrow()
            }

        }
    } - {

        test("process with code after credential offer, and scope for one credential") {
            val credentialOffer = it.authorizationService.credentialOfferWithAuthorizationCode(it.issuer.publicContext)
            val credentialIdToRequest = credentialOffer.configurationIds.first()
            val credentialFormat =
                it.issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest].shouldNotBeNull()
            val token = it.getToken(credentialOffer, credentialFormat.scope.shouldNotBeNull())
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            val credentialRequest = it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce,
            ).getOrThrow()

            val credential = it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = credentialRequest.first(),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                .response
            credential.credentials.shouldNotBeEmpty()
                .first().credentialString.shouldNotBeNull()
        }

        test("process with code after credential offer, wrong issuer_state") {
            val credentialOffer = it.authorizationService.credentialOfferWithAuthorizationCode(it.issuer.publicContext)
            val credentialIdToRequest = credentialOffer.configurationIds.first()
            val credentialFormat =
                it.issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest].shouldNotBeNull()
            val authnRequest = it.oauth2Client.createAuthRequestJar(
                state = it.state,
                scope = credentialFormat.scope.shouldNotBeNull(),
                resource = it.issuer.metadata.credentialIssuer,
                issuerState = "wrong issuer_state"
            )
            shouldThrow<OAuth2Exception> {
                it.authorizationService
                    .authorize(authnRequest as RequestParameters) { catching { DummyUserProvider.user } }
                    .getOrThrow()
            }
        }

        test("process with code after credential offer, and authorization details for one credential") {
            val credentialOffer = it.authorizationService.credentialOfferWithAuthorizationCode(it.issuer.publicContext)
            val credentialIdToRequest = credentialOffer.configurationIds.first()
            val authorizationDetails = it.client.buildAuthorizationDetails(
                credentialConfigurationId = credentialIdToRequest,
                authorizationServers = it.issuer.metadata.authorizationServers
            )
            val credentialFormat = it.issuer.metadata.supportedCredentialConfigurations
                .shouldNotBeNull()[credentialIdToRequest]
                .shouldNotBeNull()
            val token = it.getToken(credentialOffer, authorizationDetails)

            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            val credentialRequest = it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce,
            ).getOrThrow()

            val credential = it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = credentialRequest.first(),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                .response
            credential.credentials.shouldNotBeEmpty()
                .first().credentialString.shouldNotBeNull()
        }
    }
}