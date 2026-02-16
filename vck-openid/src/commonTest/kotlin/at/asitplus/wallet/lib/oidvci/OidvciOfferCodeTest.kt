package at.asitplus.wallet.lib.oidvci

import at.asitplus.catching
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
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
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.collections.listOf

val OidvciOfferCodeTest by testSuite {

    withFixtureGenerator {
        object {
            val mapper = DefaultCredentialSchemeMapper()
            val authorizationService = SimpleAuthorizationService(
                strategy = CredentialAuthorizationServiceStrategy(
                    credentialSchemes = setOf(AtomicAttribute2023, MobileDrivingLicenceScheme),
                    mapper = mapper,
                ),
            )
            val issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(AtomicAttribute2023, MobileDrivingLicenceScheme),
                credentialSchemeMapper = mapper,
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
                    issuerState = credentialOffer.grants?.authorizationCode?.issuerState
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
                    issuerState = credentialOffer.grants?.authorizationCode?.issuerState
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
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.credentialOfferWithAuthorizationCode(
                credentialIssuer = it.issuer.publicContext,
                configurationIds = setOf(credentialIdToRequest)
            )
            val credentialFormat = it.issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest]
                .shouldNotBeNull()
            val token = it.getToken(credentialOffer, credentialFormat.scope.shouldNotBeNull())
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            val request = it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce,
            ).getOrThrow().shouldBeSingleton().first()

            val credential = it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = request,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                .response
            credential.credentials.shouldNotBeEmpty()
                .first().credentialString.shouldNotBeNull()
        }

        test("process with code after credential offer, and scope for all credentials") {
            val credentialOffer = it.authorizationService.credentialOfferWithAuthorizationCode(
                credentialIssuer = it.issuer.publicContext,
                configurationIds = listOf(),
            )
            val credentialIdToRequest = credentialOffer.configurationIds.first()
            val credentialFormat = it.issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest]
                .shouldNotBeNull()
            val token = it.getToken(credentialOffer, credentialFormat.scope.shouldNotBeNull())
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            val request = it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce,
            ).getOrThrow().shouldBeSingleton().first()

            val credential = it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = request,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                .response
            credential.credentials.shouldNotBeEmpty()
                .first().credentialString.shouldNotBeNull()
        }

        test("process with code after credential offer, wrong issuer_state") {
            val credentialOffer = it.authorizationService.credentialOfferWithAuthorizationCode(
                credentialIssuer = it.issuer.publicContext,
                configurationIds = listOf(),
            )
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

        test("process with code after credential offer over par and request_uri") {
            val credentialOffer = it.authorizationService.credentialOfferWithAuthorizationCode(
                credentialIssuer = it.issuer.publicContext,
                configurationIds = listOf(),
            )
            val credentialIdToRequest = credentialOffer.configurationIds.first()
            val credentialFormat = it.issuer.metadata.supportedCredentialConfigurations
                ?.get(credentialIdToRequest)
                .shouldNotBeNull()
            val authnRequest = it.oauth2Client.createAuthRequest(
                state = it.state,
                scope = credentialFormat.scope.shouldNotBeNull(),
                resource = it.issuer.metadata.credentialIssuer,
                issuerState = credentialOffer.grants?.authorizationCode?.issuerState,
            )
            val parResponse = it.authorizationService.par(
                request = authnRequest,
                httpRequest = null
            ).getOrThrow()
            val authnResponse = it.authorizationService.authorize(
                input = it.oauth2Client.createAuthRequestAfterPar(parResponse),
                loadUserFun = { catching { DummyUserProvider.user } }
            ).getOrThrow().shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            authnResponse.params?.code.shouldNotBeNull()
        }

        test("process with code after credential offer, and authorization details for one credential") {
            val credentialOffer = it.authorizationService.credentialOfferWithAuthorizationCode(
                credentialIssuer = it.issuer.publicContext,
                configurationIds = listOf(),
            )
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

            val request = it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce,
            ).getOrThrow().shouldBeSingleton().first()

            val credential = it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = request,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                .response
            credential.credentials.shouldNotBeEmpty()
                .first().credentialString.shouldNotBeNull()
        }

        test("process with code after credential offer, but wrong issuer state fails") {
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.credentialOfferWithAuthorizationCode(
                credentialIssuer = it.issuer.publicContext,
                configurationIds = setOf(credentialIdToRequest)
            )
            val credentialFormat = it.issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest]
                .shouldNotBeNull()
            // important step: mess with the issuer state, so the wallet sends an incorrect one
            val malignAuthCode = credentialOffer.grants.shouldNotBeNull().authorizationCode.shouldNotBeNull()
                .copy(issuerState = "wrong issuer state")
            val malignOffer = credentialOffer.copy(
                grants = credentialOffer.grants.shouldNotBeNull().copy(authorizationCode = malignAuthCode)
            )
            shouldThrow<OAuth2Exception.InvalidGrant> {
                it.getToken(malignOffer, credentialFormat.scope.shouldNotBeNull())
            }
        }

        test("process with code after credential offer, but scope not covered offer fails") {
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.credentialOfferWithAuthorizationCode(
                credentialIssuer = it.issuer.publicContext,
                configurationIds = setOf(credentialIdToRequest)
            )
            val otherCredentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, ISO_MDOC)
            // important step: mess with the scope value
            val malignScope = it.issuer.metadata.supportedCredentialConfigurations!![otherCredentialIdToRequest]
                .shouldNotBeNull().scope.shouldNotBeNull().reversed()
            shouldThrow<OAuth2Exception.InvalidScope> {
                it.getToken(credentialOffer, malignScope)
            }
        }

        test("process with code after credential offer, but wrong authorization details should fail") {
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.credentialOfferWithAuthorizationCode(
                credentialIssuer = it.issuer.publicContext,
                configurationIds = setOf(credentialIdToRequest)
            )
            val otherCredentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, ISO_MDOC)
            // important step: mess with the authorization details
            val authorizationDetails = it.client.buildAuthorizationDetails(
                credentialConfigurationId = otherCredentialIdToRequest,
                authorizationServers = it.issuer.metadata.authorizationServers
            )
            shouldThrow<OAuth2Exception.InvalidAuthorizationDetails> {
                it.getToken(credentialOffer, authorizationDetails)
            }
        }

    }
}
