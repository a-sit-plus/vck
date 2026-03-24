package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialRequestProofContainer
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.openid.DummyUserProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

val OidvciPreAuthTest by testSuite {

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
                credentialIdToRequest: Set<String>,
            ): TokenResponseParameters {
                val preAuth = credentialOffer.grants?.preAuthorizedCode.shouldNotBeNull()
                val tokenRequest = oauth2Client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth.preAuthorizedCode),
                    authorizationDetails = client.buildAuthorizationDetails(
                        credentialConfigurationIds = credentialIdToRequest,
                        authorizationServers = issuer.metadata.authorizationServers
                    )
                )
                return authorizationService.token(tokenRequest, null).getOrThrow()
            }
        }
    } - {
        test("process with pre-authorized code, credential offer, and authorization details for one credential") {
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.credentialOfferWithPreAuthnForUser(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                configurationIds = setOf(credentialIdToRequest)
            )
            val credentialFormat = it.issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest]
                .shouldNotBeNull()

            val token = it.getToken(credentialOffer, setOf(credentialIdToRequest))
            token.authorizationDetails.shouldNotBeNull()
                .first().shouldBeInstanceOf<OpenIdAuthorizationDetails>()
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

        test("process with pre-authorized code, credential offer, and authorization details for all credentials") {
            val credentialOffer = it.authorizationService.credentialOfferWithPreAuthnForUser(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext
            )
            val credentialIdsToRequest = credentialOffer.configurationIds
                .shouldHaveSize(4) // Atomic Attribute in 3 representations (JWT, ISO, dc+sd-jwt), mDL in ISO
                .toSet()

            val token = it.getToken(credentialOffer, credentialIdsToRequest)
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce
            val authnDetails = token.authorizationDetails
                .shouldNotBeNull()
                .shouldHaveSize(4)

            authnDetails.forEach { authnDetail ->
                authnDetail.shouldBeInstanceOf<OpenIdAuthorizationDetails>()
                val credentialFormat = it.issuer.metadata.supportedCredentialConfigurations
                    .shouldNotBeNull()[authnDetail.credentialIdentifiers.shouldNotBeNull().first()]
                    .shouldNotBeNull()
                it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = it.client.createCredential(
                        tokenResponse = token,
                        metadata = it.issuer.metadata,
                        credentialFormat = credentialFormat,
                        clientNonce = clientNonce,
                    ).getOrThrow().first(),
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
                    .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                    .response
                    .credentials.shouldNotBeEmpty().first()
                    .credentialString.shouldNotBeNull()
            }
        }

        test("process with pre-authorized code, credential offer, and scope") {
            val credentialOffer = it.authorizationService.credentialOfferWithPreAuthnForUser(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext
            )
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            // OID4VCI 5.1.2 Using scope Parameter to Request Issuance of a Credential
            val supportedCredentialFormat =
                it.issuer.metadata.supportedCredentialConfigurations?.get(credentialIdToRequest)
                    .shouldNotBeNull()
            val scope = supportedCredentialFormat.scope
                .shouldNotBeNull()

            val preAuth = credentialOffer.grants?.preAuthorizedCode
                .shouldNotBeNull()
            val tokenRequest = it.oauth2Client.createTokenRequestParameters(
                state = it.state,
                authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth.preAuthorizedCode),
                scope = scope,
                resource = it.issuer.metadata.credentialIssuer,
            )
            val token = it.authorizationService.token(tokenRequest, null).getOrThrow()
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            val request = it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = supportedCredentialFormat,
                clientNonce = clientNonce,
            ).getOrThrow().shouldBeSingleton().first()

            it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = request,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                .response
                .credentials.shouldNotBeEmpty().first()
                .credentialString.shouldNotBeNull()
        }

        test("two proofs over different keys lead to two credentials") {
            val credentialOffer = it.authorizationService.credentialOfferWithPreAuthnForUser(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext
            )
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)

            val token = it.getToken(credentialOffer, setOf(credentialIdToRequest))
            val credentialIdentifier = token.authorizationDetails.shouldNotBeNull()
                .filterIsInstance<OpenIdAuthorizationDetails>()
                .first().credentialIdentifiers.shouldNotBeNull().first()

            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce
            val proof = it.client.createCredentialRequestProofJwt(
                clientNonce = clientNonce,
                credentialIssuer = it.issuer.metadata.credentialIssuer,
            )
            val differentProof = WalletService().createCredentialRequestProofJwt(
                clientNonce = clientNonce,
                credentialIssuer = it.issuer.metadata.credentialIssuer,
            )

            val credentialRequest = CredentialRequestParameters(
                credentialIdentifier = credentialIdentifier,
                proofs = CredentialRequestProofContainer(
                    jwt = proof.jwt!! + differentProof.jwt!!
                )
            )

            val credentials = it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = WalletService.CredentialRequest.Plain(credentialRequest),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                .response
                .credentials.shouldNotBeEmpty()
                .shouldHaveSize(2)
            // subject identifies the key of the client, here the keys of different proofs, so they should be unique
            credentials.map {
                JwsCompact.parse<VerifiableCredentialJws>(
                    it.credentialString.shouldNotBeNull(),
                ).getOrThrow().second.subject
            }.toSet().shouldHaveSize(2)
        }

    }
}
