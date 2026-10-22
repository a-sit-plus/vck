package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersSerializer
import at.asitplus.openid.SupportedCredentialFormatIsoMdoc
import at.asitplus.openid.SupportedCredentialFormatSdJwt
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.decodeFromFormUrlEncoded
import at.asitplus.openid.toFormParameters
import at.asitplus.signum.indispensable.josef.ClientStatus
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.eupid.EU_PID_DOCTYPE
import at.asitplus.wallet.eupid.EuPidDataElements
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtDataElements
import at.asitplus.wallet.lib.HttpErrorResponseException
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemoryIssuerCredentialStore
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.ktor.openid.TestUtils.credentialDataProviderFun
import at.asitplus.wallet.lib.ktor.openid.TestUtils.dummyUser
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respond
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondOAuth2Error
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondResourceServerError
import at.asitplus.wallet.lib.oauth2.AttestationBasedClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.ClientAttestation
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.TokenService
import at.asitplus.wallet.lib.oauth2.toHttpResponse
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.CredentialDataProviderFun
import at.asitplus.wallet.lib.oidvci.CredentialIdentifierInfo
import at.asitplus.wallet.lib.oidvci.JwtProofCreator
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OpenId4VciClient
import at.asitplus.wallet.lib.oidvci.OpenId4VciServer
import at.asitplus.wallet.lib.oidvci.ProofValidator
import at.asitplus.wallet.lib.oidvci.ReceivedCredential
import at.asitplus.wallet.lib.oidvci.toHttpResponse
import at.asitplus.wallet.lib.validation.CredentialValidationInput
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidationDecision
import at.asitplus.wallet.lib.validation.ValidationPolicy
import io.github.aakira.napier.Napier
import io.kotest.engine.runBlocking
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

/**
 * Tests [OpenId4VciKtorClient] requesting credentials of several configurations in one flow, i.e. with one
 * authorization and one token, against [OpenId4VciServer], which accepts each `c_nonce` only once.
 */
val OpenId4VciKtorClientMultipleCredentialsTest by matrixSuite {

    /** The EU PID as SD-JWT VC and as ISO mdoc, i.e. credentials of different formats from one issuer. */
    class Context(
        val credentialKeyMaterial: KeyMaterial,
        val mockEngine: MockEngine,
        val authorizationService: SimpleAuthorizationService,
        val openId4VciServer: OpenId4VciServer,
        val client: OpenId4VciKtorClient,
        /** Paths of every request the client sent, in order. */
        val sentPaths: MutableList<String>,
        /** Answers this many credential requests with `invalid_nonce` before issuing. */
        var invalidNonceAnswers: Int = 0,
    ) {
        val sdJwtScheme = runBlocking { AttributeIndex.resolveIdentifier(EU_PID_SD_JWT_VCT, SD_JWT) }
        val isoScheme = runBlocking { AttributeIndex.resolveIdentifier(EU_PID_DOCTYPE, ISO_MDOC) }

        fun count(path: String) = sentPaths.count { it == path }

        /**
         * Whether every credential request uses the token obtained before the first of them, i.e. no token request,
         * also not a retry for a DPoP nonce (`Token{1,2}`), is sent after the credential requests began.
         */
        fun oneTokenForAllCredentials() =
            sentPaths.indexOfLast { it == "/token" } < sentPaths.indexOfFirst { it == "/credential" }

        suspend fun selection(): List<CredentialIdentifierInfo> {
            val infos = client.loadCredentialMetadata("https://issuer.example.com").getOrThrow()
            return listOf(
                infos.first {
                    (it.supportedCredentialFormat as? SupportedCredentialFormatSdJwt)?.sdJwtVcType == EU_PID_SD_JWT_VCT
                },
                infos.first {
                    (it.supportedCredentialFormat as? SupportedCredentialFormatIsoMdoc)?.docType == EU_PID_DOCTYPE
                },
            )
        }

        suspend fun preAuthorizedOffer(vararg schemes: Pair<CredentialScheme, CredentialRepresentation>) =
            authorizationService.offerWithPreAuthnForUserForSchemes(
                user = dummyUser(),
                credentialIssuer = openId4VciServer.metadata.credentialIssuer,
                schemes = schemes.toSet(),
            )
    }

    val attributes: Map<CredentialRepresentation, Map<String, String>> = mapOf(
        SD_JWT to mapOf(EuPidSdJwtDataElements.FAMILY_NAME to "Doe"),
        ISO_MDOC to mapOf(EuPidDataElements.GIVEN_NAME to "Jane"),
    )

    // The issuer's certificate is self-signed, and its status list is not published in this test
    val integrityOnly = ValidationPolicy(
        trust = TrustPolicy.IntegrityOnly,
        status = StatusPolicy.Skip,
        timeLeeway = 5.minutes,
        requireTimeliness = true,
    )

    fun setup(): Context {
        val walletProvider = runBlocking { TestWalletProvider() }
        val credentialKeyMaterial = EphemeralKeyWithoutCert()
        val clientAuthKeyMaterial = EphemeralKeyWithoutCert()
        val credentialSchemes = runBlocking {
            setOf(
                AttributeIndex.resolveIdentifier(EU_PID_SD_JWT_VCT, SD_JWT),
                AttributeIndex.resolveIdentifier(EU_PID_DOCTYPE, ISO_MDOC),
            )
        }
        val publicContext = "https://issuer.example.com"
        val authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(credentialSchemes),
            publicContext = publicContext,
            authorizationEndpointPath = "/authorize",
            tokenEndpointPath = "/token",
            pushedAuthorizationRequestEndpointPath = "/par",
            challengeEndpointPath = "/challenge",
            clientAuthenticationService = AttestationBasedClientAuthenticationService(
                clientAttestationValidator = walletProvider.clientAttestationValidator,
            ),
            tokenService = TokenService.jwt(issueRefreshTokens = true),
        )
        val openId4VciServer = OpenId4VciServer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                issuerCredentialStore = InMemoryIssuerCredentialStore(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            ),
            credentialSchemes = credentialSchemes,
            publicContext = publicContext,
            credentialEndpointPath = "/credential",
            nonceEndpointPath = "/nonce",
            proofValidator = ProofValidator(publicContext = publicContext),
        )
        // Issues the scheme and representation of each request, instead of a single one
        val credentialDataProvider = CredentialDataProviderFun { input ->
            credentialDataProviderFun(
                scheme = input.credentialScheme,
                representation = input.credentialRepresentation,
                attributes = attributes.getValue(input.credentialRepresentation),
            ).invoke(input)
        }
        val sentPaths = mutableListOf<String>()
        lateinit var context: Context
        val mockEngine = MockEngine { request ->
            sentPaths += request.url.encodedPath
            when {
                request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.CredentialIssuer ->
                    respond(openId4VciServer.metadataHttpResponse(request.headers[HttpHeaders.Accept]).getOrThrow())

                request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.OauthAuthorizationServer ->
                    respond(authorizationService.metadata().toHttpResponse())

                request.url.fullPath.startsWith("/par") -> {
                    val authnRequest: RequestParameters = RequestParametersSerializer.decodeFormParameters(
                        request.body.toByteArray().decodeToString().toFormParameters()
                    )
                    authorizationService.parWithDpopNonce(authnRequest, request.toRequestInfo()).fold(
                        onSuccess = { respond(it.toHttpResponse()) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith("/authorize") -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: RequestParameters = if (requestBody.isEmpty())
                        RequestParametersSerializer.decodeFormParameters(
                            request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                        )
                    else RequestParametersSerializer.decodeFormParameters(requestBody.toFormParameters())
                    authorizationService.authorize(authnRequest) { catching { dummyUser() } }.fold(
                        onSuccess = { respond(it.toHttpResponse()) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith("/token") -> {
                    val params = request.body.toByteArray().decodeToString()
                        .decodeFromFormUrlEncoded<TokenRequestParameters>()
                    authorizationService.tokenWithDpopNonce(params, request.toRequestInfo()).fold(
                        onSuccess = { respond(it.toHttpResponse()) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith("/nonce") ->
                    respond(openId4VciServer.nonceWithDpopNonce().getOrThrow().toHttpResponse())

                request.url.fullPath.startsWith("/challenge") ->
                    respond(authorizationService.attestationChallenge().getOrThrow().shouldNotBeNull().toHttpResponse())

                request.url.fullPath.startsWith("/credential") -> {
                    val authn = request.headers[HttpHeaders.Authorization].shouldNotBeNull()
                    if (context.invalidNonceAnswers > 0) {
                        context.invalidNonceAnswers--
                        respondResourceServerError(OAuth2Exception.InvalidNonce("nonce rejected"), authn)
                    } else openId4VciServer.credential(
                        authorizationHeader = authn,
                        params = OpenId4VciClient.CredentialRequest.parse(request.body.toByteArray().decodeToString())
                            .getOrThrow(),
                        credentialDataProvider = credentialDataProvider,
                        request = request.toRequestInfo(),
                    ).fold(
                        onSuccess = { respond(it.toHttpResponse()) },
                        onFailure = { respondResourceServerError(it, authn) }
                    )
                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        }
        val clientId = "https://example.com/rp"
        context = Context(
            credentialKeyMaterial = credentialKeyMaterial,
            mockEngine = mockEngine,
            authorizationService = authorizationService,
            openId4VciServer = openId4VciServer,
            client = OpenId4VciKtorClient(
                httpClient = HttpClient(mockEngine),
                oauth2Client = OAuth2Client(clientId = clientId),
                vciClient = OpenId4VciClient(proofCreators = listOf(JwtProofCreator(credentialKeyMaterial))),
                clientAttestation = ClientAttestation(clientAuthKeyMaterial) {
                    catching {
                        BuildClientAttestationJwt(
                            walletProvider.signJwt,
                            clientId = clientId,
                            clientKey = clientAuthKeyMaterial.jsonWebKey,
                            clientStatus = ClientStatus(buildJsonObject { }, Clock.System.now().plus(5.minutes)),
                        )
                    }
                },
            ),
            sentPaths = sentPaths,
        )
        return context
    }

    /** Both groups carry the credential of their own format, bound to the holder's key, with own renewal info. */
    suspend fun Context.verifyIssued(
        success: CredentialIssuanceResult.Success,
        selection: List<CredentialIdentifierInfo>,
    ) {
        success.issued.map { it.credentialIdentifierInfo } shouldContainExactly selection
        success.issued[0].apply {
            scheme shouldBe sdJwtScheme
            receivedCredentials.shouldBeSingleton().first().shouldBeInstanceOf<ReceivedCredential.Decoded>()
                .input.shouldBeInstanceOf<CredentialValidationInput.SdJwtVc>()
            refreshToken.shouldNotBeNull().credentialIdentifier shouldBe selection[0].credentialIdentifier
        }
        success.issued[1].apply {
            scheme shouldBe isoScheme
            receivedCredentials.shouldBeSingleton().first().shouldBeInstanceOf<ReceivedCredential.Decoded>()
                .input.shouldBeInstanceOf<CredentialValidationInput.IsoMdoc>()
            refreshToken.shouldNotBeNull().credentialIdentifier shouldBe selection[1].credentialIdentifier
        }
        success.prepareCredentialStorage(HolderAgent(credentialKeyMaterial), integrityOnly).getOrThrow()
            .shouldHaveSize(2)
            .forEach { it.validation.report.decision shouldBe ValidationDecision.ACCEPTED }
    }

    "pre-authorized offer of credentials of different formats issues all of them with one token" {
        with(setup()) {
            val selection = selection()
            val offer = preAuthorizedOffer(sdJwtScheme to SD_JWT, isoScheme to ISO_MDOC)

            val success = client.loadCredentialWithOfferReturningResult(offer, selection.toNonEmptyList())
                .getOrThrow().shouldBeInstanceOf<CredentialIssuanceResult.Success>()

            verifyIssued(success, selection)
            oneTokenForAllCredentials() shouldBe true
            // One fresh c_nonce per credential request, as the issuer accepts each one only once
            count("/nonce") shouldBe 2
        }
    }

    "authorization code flow for credentials of different formats authorizes once" {
        with(setup()) {
            val selection = selection()

            val openUrl = client.startProvisioningWithAuthRequestReturningResult(
                credentialIssuerUrl = "https://issuer.example.com",
                credentialIdentifierInfos = selection.toNonEmptyList(),
            ).getOrThrow()
            openUrl.context.credentials shouldContainExactly selection
            // Simulates the browser, handling authorization to get the authCode
            val authCode = HttpClient(mockEngine) { followRedirects = false }
                .get(openUrl.url).headers[HttpHeaders.Location].shouldNotBeNull()
            val success = client.resumeWithAuthCode(authCode, openUrl.context).getOrThrow()

            verifyIssued(success, selection)
            count("/authorize") shouldBe 1
            oneTokenForAllCredentials() shouldBe true
            count("/nonce") shouldBe 2
        }
    }

    "a credential request rejected with invalid_nonce is sent once more with a new nonce" {
        with(setup()) {
            invalidNonceAnswers = 1
            val selection = selection().take(1)
            val offer = preAuthorizedOffer(sdJwtScheme to SD_JWT)

            client.loadCredentialWithOfferReturningResult(offer, selection.toNonEmptyList()).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuanceResult.Success>()
                .issued.shouldBeSingleton().first().receivedCredentials.shouldBeSingleton()
            count("/nonce") shouldBe 2
        }
    }

    "a credential request rejected with invalid_nonce twice fails" {
        with(setup()) {
            invalidNonceAnswers = 2
            val selection = selection().take(1)
            val offer = preAuthorizedOffer(sdJwtScheme to SD_JWT)

            client.loadCredentialWithOfferReturningResult(offer, selection.toNonEmptyList()).exceptionOrNull()
                .shouldBeInstanceOf<HttpErrorResponseException>()
                .oauth2Error.shouldNotBeNull().error shouldBe OpenIdConstants.Errors.INVALID_NONCE
            count("/nonce") shouldBe 2
        }
    }

    "provisioning context stored by an earlier version requests its only credential" {
        with(setup()) {
            val credential = selection().first()
            val stored = joseCompliantSerializer.encodeToJsonElement(
                ProvisioningContext.serializer(),
                ProvisioningContext(
                    state = "state",
                    credential = credential,
                    oauthMetadata = authorizationService.metadata(),
                    issuerMetadata = openId4VciServer.metadata,
                )
            ).jsonObject.let { JsonObject(it - "credentials") }

            joseCompliantSerializer.decodeFromJsonElement(ProvisioningContext.serializer(), stored)
                .credentials shouldContainExactly listOf(credential)
        }
    }
}
