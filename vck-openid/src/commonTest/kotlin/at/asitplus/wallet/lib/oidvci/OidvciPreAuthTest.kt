package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.*
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.DummyOAuth2DataProvider
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

class OidvciPreAuthTest : FreeSpec({

    lateinit var authorizationService: SimpleAuthorizationService
    lateinit var issuer: CredentialIssuer
    lateinit var client: WalletService
    lateinit var state: String

    beforeEach {
        authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(setOf(AtomicAttribute2023, MobileDrivingLicenceScheme)),
            dataProvider = DummyOAuth2DataProvider,
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            credentialSchemes = setOf(AtomicAttribute2023, MobileDrivingLicenceScheme),
        )
        client = WalletService()
        state = uuid4().toString()
    }

    suspend fun getToken(
        credentialOffer: CredentialOffer,
        credentialIdToRequest: Set<String>,
    ): TokenResponseParameters {
        val preAuth = credentialOffer.grants?.preAuthorizedCode.shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth.preAuthorizedCode),
            authorizationDetails = client.buildAuthorizationDetails(
                credentialIdToRequest,
                issuer.metadata.authorizationServers
            )
        )
        return authorizationService.token(tokenRequest).getOrThrow()
    }

    "process with pre-authorized code, credential offer, and authorization details for one credential" {
        val credentialOffer =
            authorizationService.credentialOfferWithPreAuthnForUser(DummyOAuth2DataProvider.user, issuer.publicContext)
        val credentialIdToRequest = AtomicAttribute2023.toCredentialIdentifier(PLAIN_JWT)
        val credentialFormat =
            issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest].shouldNotBeNull()

        val token = getToken(credentialOffer, setOf(credentialIdToRequest))
        token.authorizationDetails.shouldNotBeNull()
            .first().shouldBeInstanceOf<OpenIdAuthorizationDetails>()
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
            issueCredential = { IssuerAgent().issueCredential(it) }
        ).getOrThrow()
        credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()
    }

    "process with pre-authorized code, credential offer, and authorization details for all credentials" {
        val credentialOffer =
            authorizationService.credentialOfferWithPreAuthnForUser(DummyOAuth2DataProvider.user, issuer.publicContext)
        val credentialIdsToRequest = credentialOffer.configurationIds
            .shouldHaveSize(5) // Atomic Attribute in 4 representations (JWT, ISO, dc+sd-jwt and vc+sd-jwt), mDL in ISO
            .toSet()

        val token = getToken(credentialOffer, credentialIdsToRequest)
        val clientNonce = issuer.nonce().getOrThrow().clientNonce
        val authnDetails = token.authorizationDetails
            .shouldNotBeNull()
            .shouldHaveSize(5)

        authnDetails.forEach {
            it.shouldBeInstanceOf<OpenIdAuthorizationDetails>()
            val credentialFormat =
                issuer.metadata.supportedCredentialConfigurations!![it.credentialIdentifiers!!.first()].shouldNotBeNull()
            val credentialRequest = client.createCredentialRequest(
                tokenResponse = token,
                metadata = issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce,
            ).getOrThrow()

            issuer.credential(
                token.toHttpHeaderValue(),
                credentialRequest.first(),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                issueCredential = { IssuerAgent().issueCredential(it) }
            ).getOrThrow()
                .credentials.shouldNotBeEmpty().first()
                .credentialString.shouldNotBeNull()
        }
    }

    "process with pre-authorized code, credential offer, and scope" {
        val credentialOffer =
            authorizationService.credentialOfferWithPreAuthnForUser(DummyOAuth2DataProvider.user, issuer.publicContext)
        val credentialIdToRequest = AtomicAttribute2023.toCredentialIdentifier(PLAIN_JWT)
        // OID4VCI 5.1.2 Using scope Parameter to Request Issuance of a Credential
        val supportedCredentialFormat = issuer.metadata.supportedCredentialConfigurations?.get(credentialIdToRequest)
            .shouldNotBeNull()
        val scope = supportedCredentialFormat.scope
            .shouldNotBeNull()

        val preAuth = credentialOffer.grants?.preAuthorizedCode
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth.preAuthorizedCode),
            scope = scope,
            resource = issuer.metadata.credentialIssuer,
        )
        val token = authorizationService.token(tokenRequest).getOrThrow()
        val clientNonce = issuer.nonce().getOrThrow().clientNonce

        val credentialRequest = client.createCredentialRequest(
            tokenResponse = token,
            metadata = issuer.metadata,
            credentialFormat = supportedCredentialFormat,
            clientNonce = clientNonce,
        ).getOrThrow()

        issuer.credential(
            token.toHttpHeaderValue(),
            credentialRequest.first(),
            credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            issueCredential = { IssuerAgent().issueCredential(it) }
        ).getOrThrow()
            .credentials.shouldNotBeEmpty().first()
            .credentialString.shouldNotBeNull()
    }

    "two proofs over different keys lead to two credentials" {
        val credentialOffer =
            authorizationService.credentialOfferWithPreAuthnForUser(DummyOAuth2DataProvider.user, issuer.publicContext)
        val credentialIdToRequest = AtomicAttribute2023.toCredentialIdentifier(PLAIN_JWT)

        val token = getToken(credentialOffer, setOf(credentialIdToRequest))
        val credentialIdentifier = token.authorizationDetails.shouldNotBeNull()
            .filterIsInstance<OpenIdAuthorizationDetails>()
            .first().credentialIdentifiers.shouldNotBeNull().first()

        val clientNonce = issuer.nonce().getOrThrow().clientNonce
        val proof = client.createCredentialRequestProofJwt(
            clientNonce = clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer,
        )
        val differentProof = WalletService().createCredentialRequestProofJwt(
            clientNonce = clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer,
        )

        val credentialRequest = CredentialRequestParameters(
            credentialIdentifier = credentialIdentifier,
            proofs = CredentialRequestProofContainer(
                jwt = setOf(proof.jwt!!, differentProof.jwt!!)
            )
        )

        val credentials = issuer.credential(
            token.toHttpHeaderValue(),
            credentialRequest,
            credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            issueCredential = { IssuerAgent().issueCredential(it) }
        ).getOrThrow()
            .credentials.shouldNotBeEmpty()
            .shouldHaveSize(2)
        // subject identifies the key of the client, here the keys of different proofs, so they should be unique
        credentials.map {
            JwsSigned.deserialize<VerifiableCredentialJws>(
                VerifiableCredentialJws.serializer(),
                it.credentialString.shouldNotBeNull(),
                vckJsonSerializer
            ).getOrThrow().payload.subject
        }.toSet().shouldHaveSize(2)
    }

})