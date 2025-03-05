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
            strategy = CredentialAuthorizationServiceStrategy(
                DummyOAuth2DataProvider,
                setOf(AtomicAttribute2023, MobileDrivingLicenceScheme)
            ),
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(),
            credentialSchemes = setOf(AtomicAttribute2023, MobileDrivingLicenceScheme),
            credentialProvider = DummyOAuth2IssuerCredentialDataProvider
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
        val credentialOffer = issuer.credentialOfferWithPreAuthnForUser(DummyOAuth2DataProvider.user)
        val credentialIdToRequest = AtomicAttribute2023.toCredentialIdentifier(PLAIN_JWT)
        val credentialFormat = issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest].shouldNotBeNull()

        val token = getToken(credentialOffer, setOf(credentialIdToRequest))
        token.authorizationDetails.shouldNotBeNull()
            .first().shouldBeInstanceOf<OpenIdAuthorizationDetails>()

        val credentialRequest = client.createCredentialRequest(
            tokenResponse = token,
            metadata = issuer.metadata,
            credentialFormat = credentialFormat,
        ).getOrThrow()

        val credential = issuer.credential(token.accessToken, credentialRequest.first())
            .getOrThrow()
        credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()
    }

    "process with pre-authorized code, credential offer, and authorization details for all credentials" {
        val credentialOffer = issuer.credentialOfferWithPreAuthnForUser(DummyOAuth2DataProvider.user)
        val credentialIdsToRequest = credentialOffer.configurationIds
            .shouldHaveSize(4) // Atomic Attribute in 3 representations, mDL in ISO
            .toSet()

        val token = getToken(credentialOffer, credentialIdsToRequest)
        val authnDetails = token.authorizationDetails
            .shouldNotBeNull()
            .shouldHaveSize(4)

        authnDetails.forEach {
            it.shouldBeInstanceOf<OpenIdAuthorizationDetails>()
            val credentialFormat = issuer.metadata.supportedCredentialConfigurations!![it.credentialIdentifiers!!.first()].shouldNotBeNull()
            val credentialRequest = client.createCredentialRequest(
                tokenResponse = token,
                metadata = issuer.metadata,
                credentialFormat = credentialFormat,
            ).getOrThrow()

            issuer.credential(token.accessToken, credentialRequest.first())
                .getOrThrow()
                .credentials.shouldNotBeEmpty().first()
                .credentialString.shouldNotBeNull()
        }
    }

    "process with pre-authorized code, credential offer, and scope" {
        val credentialOffer = issuer.credentialOfferWithPreAuthnForUser(DummyOAuth2DataProvider.user)
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

        val credentialRequest = client.createCredentialRequest(
            tokenResponse = token,
            metadata = issuer.metadata,
            credentialFormat = supportedCredentialFormat,
        ).getOrThrow()

        issuer.credential(token.accessToken, credentialRequest.first())
            .getOrThrow()
            .credentials.shouldNotBeEmpty().first()
            .credentialString.shouldNotBeNull()
    }

    "two proofs over different keys lead to two credentials" {
        val credentialOffer = issuer.credentialOfferWithPreAuthnForUser(DummyOAuth2DataProvider.user)
        val credentialIdToRequest = AtomicAttribute2023.toCredentialIdentifier(PLAIN_JWT)

        val token = getToken(credentialOffer, setOf(credentialIdToRequest))
        val credentialIdentifier = token.authorizationDetails.shouldNotBeNull()
            .filterIsInstance<OpenIdAuthorizationDetails>()
            .first().credentialIdentifiers.shouldNotBeNull().first()

        val proof = client.createCredentialRequestProofJwt(
            clientNonce = token.clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer,
        )
        val differentProof = WalletService().createCredentialRequestProofJwt(
            clientNonce = token.clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer,
        )

        val credentialRequest = CredentialRequestParameters(
            credentialIdentifier = credentialIdentifier,
            proofs = CredentialRequestProofContainer(
                proofType = OpenIdConstants.ProofType.JWT,
                jwt = setOf(proof.jwt!!, differentProof.jwt!!)
            )
        )

        val credentials = issuer.credential(token.accessToken, credentialRequest)
            .getOrThrow()
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