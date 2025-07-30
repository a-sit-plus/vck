package at.asitplus.wallet.lib.oidvci

import at.asitplus.catching
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyUserProvider
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

class OidvciOfferCodeTest : FreeSpec({

    lateinit var authorizationService: SimpleAuthorizationService
    lateinit var issuer: CredentialIssuer
    lateinit var client: WalletService
    lateinit var state: String

    beforeEach {
        authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(setOf(AtomicAttribute2023, MobileDrivingLicenceScheme)),
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(identifier = "https://issuer.example.com".toUri()),
            credentialSchemes = setOf(AtomicAttribute2023, MobileDrivingLicenceScheme),
        )
        client = WalletService()
        state = uuid4().toString()
    }

    suspend fun getToken(
        credentialOffer: CredentialOffer,
        scope: String,
    ): TokenResponseParameters {
        val authnRequest = client.oauth2Client.createAuthRequest(
            state = state,
            scope = scope,
            resource = issuer.metadata.credentialIssuer,
            issuerState = credentialOffer.grants?.authorizationCode.shouldNotBeNull().issuerState
        )
        val authnResponse = authorizationService.authorize(authnRequest) { catching { DummyUserProvider.user } }
            .getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            scope = scope,
            resource = issuer.metadata.credentialIssuer
        )
        return authorizationService.token(tokenRequest).getOrThrow()
    }

    suspend fun getToken(
        credentialOffer: CredentialOffer,
        authorizationDetails: Set<AuthorizationDetails>,
    ): TokenResponseParameters {
        val authnRequest = client.oauth2Client.createAuthRequest(
            state = state,
            authorizationDetails = authorizationDetails,
            issuerState = credentialOffer.grants?.authorizationCode.shouldNotBeNull().issuerState
        )
        val authnResponse = authorizationService.authorize(authnRequest) { catching { DummyUserProvider.user } }
            .getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            authorizationDetails = authorizationDetails,
        )
        return authorizationService.token(tokenRequest).getOrThrow()
    }

    "process with code after credential offer, and scope for one credential" {
        val credentialOffer = authorizationService.credentialOfferWithAuthorizationCode(issuer.publicContext)
        val credentialIdToRequest = credentialOffer.configurationIds.first()
        val credentialFormat =
            issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest].shouldNotBeNull()
        val token = getToken(credentialOffer, credentialFormat.scope.shouldNotBeNull())
        val clientNonce = issuer.nonce().getOrThrow().clientNonce

        val credentialRequest = client.createCredentialRequest(
            tokenResponse = token,
            metadata = issuer.metadata,
            credentialFormat = credentialFormat,
            clientNonce = clientNonce,
        ).getOrThrow()

        val credential = issuer.credential(
            authorizationHeader = token.toHttpHeaderValue(),
            params = credentialRequest.first(),
            credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
        ).getOrThrow()
        credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()
    }

    "process with code after credential offer, wrong issuer_state" {
        val credentialOffer = authorizationService.credentialOfferWithAuthorizationCode(issuer.publicContext)
        val credentialIdToRequest = credentialOffer.configurationIds.first()
        val credentialFormat =
            issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest].shouldNotBeNull()
        val authnRequest = client.oauth2Client.createAuthRequest(
            state = state,
            scope = credentialFormat.scope.shouldNotBeNull(),
            resource = issuer.metadata.credentialIssuer,
            issuerState = "wrong issuer_state"
        )
        shouldThrow<OAuth2Exception> {
            authorizationService
                .authorize(authnRequest) { catching { DummyUserProvider.user } }
                .getOrThrow()
        }
    }

    "process with code after credential offer, and authorization details for one credential" {
        val credentialOffer = authorizationService.credentialOfferWithAuthorizationCode(issuer.publicContext)
        val credentialIdToRequest = credentialOffer.configurationIds.first()
        val authorizationDetails = client.buildAuthorizationDetails(
            credentialConfigurationId = credentialIdToRequest,
            authorizationServers = issuer.metadata.authorizationServers
        )
        val credentialFormat = issuer.metadata.supportedCredentialConfigurations
            .shouldNotBeNull()[credentialIdToRequest]
            .shouldNotBeNull()
        val token = getToken(credentialOffer, authorizationDetails)

        val clientNonce = issuer.nonce().getOrThrow().clientNonce

        val credentialRequest = client.createCredentialRequest(
            tokenResponse = token,
            metadata = issuer.metadata,
            credentialFormat = credentialFormat,
            clientNonce = clientNonce,
        ).getOrThrow()

        val credential = issuer.credential(
            authorizationHeader = token.toHttpHeaderValue(),
            params = credentialRequest.first(),
            credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
        ).getOrThrow()
        credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()
    }

})
