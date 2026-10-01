package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.CredentialOfferGrantsPreAuthCodeTransactionCode
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialRequestProofContainer
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.openid.DummyUserProvider
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowExactly
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

val OidvciPreAuthTest by matrixSuite {

    fixture {
        object {
            val mapper = DefaultCredentialSchemeMapper()
            val authorizationService = SimpleAuthorizationService(
                strategy = CredentialAuthorizationServiceStrategy(
                    credentialSchemes = AttributeIndex.schemeSet,
                    mapper = mapper,
                ),
            )
            val issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = AttributeIndex.schemeSet,
                credentialSchemeMapper = mapper,
            )
            val client = WalletService()
            val oauth2Client = OAuth2Client()
            val state = uuid4().toString()

            suspend fun getToken(
                credentialOffer: CredentialOffer,
                credentialIdToRequest: Set<String>,
                transactionCode: String? = null,
            ): TokenResponseParameters {
                val preAuth = credentialOffer.grants?.preAuthorizedCode.shouldNotBeNull()
                val tokenRequest = oauth2Client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(
                        preAuth.preAuthorizedCode,
                        transactionCode,
                    ),
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
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = setOf(AtomicAttribute2023 to PLAIN_JWT)
            )
            val credentialFormat = it.issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest]
                .shouldNotBeNull()

            val token = it.getToken(credentialOffer, setOf(credentialIdToRequest)).apply {
                authorizationDetails.shouldNotBeNull()
                    .first().shouldBeInstanceOf<OpenIdAuthorizationDetails>()
            }
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = it.client.createCredential(
                    tokenResponse = token,
                    metadata = it.issuer.metadata,
                    credentialFormat = credentialFormat,
                    clientNonce = clientNonce,
                ).getOrThrow().shouldBeSingleton().first(),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                .response.credentials.shouldNotBeEmpty()
                .first().credentialString.shouldNotBeNull()
        }

        test("client nonce can only be used for one call to credential endpoint") {
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = setOf(AtomicAttribute2023 to PLAIN_JWT)
            )
            val credentialFormat = it.issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest]
                .shouldNotBeNull()

            val token = it.getToken(credentialOffer, setOf(credentialIdToRequest)).apply {
                authorizationDetails.shouldNotBeNull()
                    .first().shouldBeInstanceOf<OpenIdAuthorizationDetails>()
            }
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = it.client.createCredential(
                    tokenResponse = token,
                    metadata = it.issuer.metadata,
                    credentialFormat = credentialFormat,
                    clientNonce = clientNonce,
                ).getOrThrow().shouldBeSingleton().first(),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                .response.credentials.shouldNotBeEmpty()
                .first().credentialString.shouldNotBeNull()

            val freshOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = setOf(AtomicAttribute2023 to PLAIN_JWT)
            )
            val freshFormat = it.issuer.metadata.supportedCredentialConfigurations!![credentialIdToRequest]
                .shouldNotBeNull()
            val freshToken = it.getToken(freshOffer, setOf(credentialIdToRequest)).apply {
                authorizationDetails.shouldNotBeNull()
                    .first().shouldBeInstanceOf<OpenIdAuthorizationDetails>()
            }
            shouldThrowExactly<OAuth2Exception.InvalidNonce> {
                it.issuer.credential(
                    authorizationHeader = freshToken.toHttpHeaderValue(),
                    params = it.client.createCredential(
                        tokenResponse = freshToken,
                        metadata = it.issuer.metadata,
                        credentialFormat = freshFormat,
                        clientNonce = clientNonce, // same as before
                    ).getOrThrow().shouldBeSingleton().first(),
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }

        test("process with pre-authorized code, credential offer, and authorization details for all credentials") {
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = emptySet(),
            )
            val credentialIdsToRequest = credentialOffer.configurationIds
                .shouldHaveSize(6) // Atomic Attribute in 3 representations (JWT, ISO, dc+sd-jwt), mDL in ISO, EUPID, EU-PID-SDJWT
                .toSet()

            val token = it.getToken(credentialOffer, credentialIdsToRequest)
            val authnDetails = token.authorizationDetails
                .shouldNotBeNull()
                .shouldHaveSize(6)

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
                        clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
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
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = emptySet(),
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
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = emptySet(),
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
                JwsCompactTyped<VerifiableCredentialJws>(
                    it.credentialString.shouldNotBeNull()
                ).payload.subject
            }.toSet().shouldHaveSize(2)
        }

        /**
         * A credential offer restricts what may be issued: the pre-authorized code must not grant every credential
         * the authorization server supports, only the configuration IDs the offer contained.
         */
        test("pre-authorized code does not grant authorization details outside the credential offer") {
            val offered = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = setOf(AtomicAttribute2023 to PLAIN_JWT),
            )
            val notOffered = it.issuer.metadata.supportedCredentialConfigurations.shouldNotBeNull()
                .keys.first { id -> id != offered }

            shouldThrow<OAuth2Exception> {
                it.getToken(credentialOffer, setOf(notOffered))
            }
        }

        test("pre-authorized code does not grant a scope outside the credential offer") {
            val offered = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = setOf(AtomicAttribute2023 to PLAIN_JWT),
            )
            val notOfferedScope = it.issuer.metadata.supportedCredentialConfigurations.shouldNotBeNull()
                .filterKeys { id -> id != offered }.values
                .firstNotNullOf { configuration -> configuration.scope }

            shouldThrow<OAuth2Exception> {
                it.authorizationService.token(
                    it.oauth2Client.createTokenRequestParameters(
                        state = it.state,
                        authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(
                            credentialOffer.grants?.preAuthorizedCode.shouldNotBeNull().preAuthorizedCode
                        ),
                        scope = notOfferedScope,
                    ),
                    null,
                ).getOrThrow()
            }
        }

        /**
         * OID4VCI 4.1.1: without a transaction code, anyone who reads the offer (e.g. photographs the QR code) can
         * redeem the pre-authorized code.
         */
        test("credential offer announces the transaction code it demands") {
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = setOf(AtomicAttribute2023 to PLAIN_JWT),
                transactionCode = "1234",
            )

            credentialOffer.grants?.preAuthorizedCode.shouldNotBeNull()
                .transactionCode.shouldNotBeNull()
                .length shouldBe 4
        }

        test("credential offer rejects inconsistent transaction code configuration") {
            shouldThrowExactly<IllegalArgumentException> {
                it.authorizationService.offerWithPreAuthnForUserForSchemes(
                    user = DummyUserProvider.user,
                    credentialIssuer = it.issuer.publicContext,
                    transactionCode = "1234",
                    transactionCodeDescriptor = null,
                )
            }
            shouldThrowExactly<IllegalArgumentException> {
                it.authorizationService.offerWithPreAuthnForUserForSchemes(
                    user = DummyUserProvider.user,
                    credentialIssuer = it.issuer.publicContext,
                    transactionCodeDescriptor = CredentialOfferGrantsPreAuthCodeTransactionCode(length = 4),
                )
            }
        }

        test("pre-authorized code is rejected without the transaction code from the offer") {
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = setOf(AtomicAttribute2023 to PLAIN_JWT),
                transactionCode = "1234",
            )

            shouldThrowExactly<OAuth2Exception.InvalidRequest> {
                it.getToken(credentialOffer, setOf(credentialIdToRequest))
            }
            it.getToken(credentialOffer, setOf(credentialIdToRequest), transactionCode = "1234")
                .accessToken.shouldNotBeNull()
        }

        test("pre-authorized code is rejected with a wrong transaction code") {
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = setOf(AtomicAttribute2023 to PLAIN_JWT),
                transactionCode = "1234",
            )

            repeat(3) { _ ->
                shouldThrowExactly<OAuth2Exception.InvalidGrant> {
                    it.getToken(credentialOffer, setOf(credentialIdToRequest), transactionCode = "9999")
                }
            }
            it.getToken(credentialOffer, setOf(credentialIdToRequest), transactionCode = "1234")
                .accessToken.shouldNotBeNull()
        }

        test("pre-authorized code is rejected with an unexpected transaction code") {
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = setOf(AtomicAttribute2023 to PLAIN_JWT),
            )

            shouldThrowExactly<OAuth2Exception.InvalidRequest> {
                it.getToken(credentialOffer, setOf(credentialIdToRequest), transactionCode = "1234")
            }
            it.getToken(credentialOffer, setOf(credentialIdToRequest))
                .accessToken.shouldNotBeNull()
        }

        test("pre-authorized code is accepted with the transaction code from the offer") {
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = setOf(AtomicAttribute2023 to PLAIN_JWT),
                transactionCode = "1234",
            )

            it.getToken(credentialOffer, setOf(credentialIdToRequest), transactionCode = "1234")
                .accessToken.shouldNotBeNull()
            shouldThrowExactly<OAuth2Exception.InvalidGrant> {
                it.getToken(credentialOffer, setOf(credentialIdToRequest), transactionCode = "1234")
            }
        }

        test("concurrent redemption with the correct transaction code succeeds exactly once") {
            val credentialIdToRequest = it.mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT)
            val credentialOffer = it.authorizationService.offerWithPreAuthnForUserForSchemes(
                user = DummyUserProvider.user,
                credentialIssuer = it.issuer.publicContext,
                schemes = setOf(AtomicAttribute2023 to PLAIN_JWT),
                transactionCode = "1234",
            )
            val start = CompletableDeferred<Unit>()

            val successes = coroutineScope {
                (1..16).map { _ ->
                    async(Dispatchers.Default) {
                        start.await()
                        runCatching {
                            it.getToken(
                                credentialOffer,
                                setOf(credentialIdToRequest),
                                transactionCode = "1234",
                            )
                        }.isSuccess
                    }
                }.also { start.complete(Unit) }.awaitAll()
            }.count { it }

            successes shouldBe 1
        }
    }
}
