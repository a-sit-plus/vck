package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.eupid.EU_PID_DOCTYPE
import at.asitplus.wallet.eupid.EuPidDataElements
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtDataElements
import at.asitplus.wallet.lib.agent.CredentialRenewalInfo
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.FixedTimePeriodProvider
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.InMemoryIssuerCredentialStore
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.StatusListAgent
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.ktor.openid.TestUtils.credentialDataProviderFun
import at.asitplus.wallet.lib.ktor.openid.TestUtils.dummyUser
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respond
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondOAuth2Error
import at.asitplus.wallet.lib.ktor.openid.TestUtils.verifyIsoMdocCredential
import at.asitplus.wallet.lib.ktor.openid.TestUtils.verifySdJwtCredential
import at.asitplus.wallet.lib.oauth2.AttestationBasedClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.TokenService
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.CredentialIssuer
import at.asitplus.wallet.lib.oidvci.ProofValidator
import at.asitplus.wallet.lib.oidvci.WalletService
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.util.*

/**
 * Tests [OpenId4VciClient] against [CredentialIssuer] with our own internal [SimpleAuthorizationService].
 */
val OpenId4VciClientTest by matrixSuite {

    data class Context(
        val credentialKeyMaterial: KeyMaterial,
        val clientAuthKeyMaterial: KeyMaterial,
        val mockEngine: MockEngine,
        val credentialIssuer: CredentialIssuer,
        val authorizationService: SimpleAuthorizationService,
        val statusListIssuer: StatusListAgent,
        val client: OpenId4VciClient,
    )

    fun setup(
        scheme: CredentialScheme,
        representation: CredentialRepresentation,
        attributes: Map<String, String>,
        revocationKind: RevocationList.Kind = RevocationList.Kind.STATUS_LIST,
    ): Context {
        val credentialKeyMaterial = EphemeralKeyWithoutCert()
        val clientAuthKeyMaterial = EphemeralKeyWithoutCert()
        val credentialSchemes = setOf(scheme)
        val authorizationEndpointPath = "/authorize"
        val tokenEndpointPath = "/token"
        val credentialEndpointPath = "/credential"
        val nonceEndpointPath = "/nonce"
        val parEndpointPath = "/par"
        val publicContext = "https://issuer.example.com"
        val authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(credentialSchemes),
            publicContext = publicContext,
            authorizationEndpointPath = authorizationEndpointPath,
            tokenEndpointPath = tokenEndpointPath,
            pushedAuthorizationRequestEndpointPath = parEndpointPath,
            clientAuthenticationService = AttestationBasedClientAuthenticationService(),
            tokenService = TokenService.jwt(
                issueRefreshTokens = true
            ),
        )
        val issuerCredentialStore = InMemoryIssuerCredentialStore()
        val issuer = IssuerAgent(
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
            issuerCredentialStore = issuerCredentialStore,
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
        val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
        val credentialIssuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = issuer,
            credentialSchemes = credentialSchemes,
            publicContext = publicContext,
            credentialEndpointPath = credentialEndpointPath,
            nonceEndpointPath = nonceEndpointPath,
            proofValidator = ProofValidator(
                publicContext = publicContext
            )
        )
        val mockEngine = MockEngine { request ->
            when {
                request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.CredentialIssuer ->
                    respond(credentialIssuer.metadata)

                request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.OauthAuthorizationServer ->
                    respond(authorizationService.metadata())

                request.url.fullPath.startsWith(parEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: RequestParameters = requestBody.decodeFromPostBody()
                    authorizationService.par(authnRequest, request.toRequestInfo()).fold(
                        onSuccess = { respond(it) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(authorizationEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val authnRequest: RequestParameters =
                        if (requestBody.isEmpty()) queryParameters.decodeFromUrlQuery()
                        else requestBody.decodeFromPostBody()
                    authorizationService.authorize(authnRequest) { catching { dummyUser() } }.fold(
                        onSuccess = { respondRedirect(it.url) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(tokenEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenRequestParameters = requestBody.decodeFromPostBody<TokenRequestParameters>()
                    authorizationService.token(params, request.toRequestInfo()).fold(
                        onSuccess = { respond(it) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(nonceEndpointPath) -> {
                    respond(credentialIssuer.nonceWithDpopNonce().getOrThrow())
                }

                request.url.fullPath.startsWith(credentialEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authn = request.headers[HttpHeaders.Authorization].shouldNotBeNull()
                    credentialIssuer.credential(
                        authorizationHeader = authn,
                        params = WalletService.CredentialRequest.parse(requestBody).getOrThrow(),
                        credentialDataProvider = credentialDataProviderFun(
                            scheme = scheme,
                            representation = representation,
                            attributes = attributes,
                            revocationKind = revocationKind,
                        ),
                        request = request.toRequestInfo(),
                    ).fold(
                        onSuccess = { respond(it) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        }
        val clientId = "https://example.com/rp"

        return Context(
            credentialKeyMaterial = credentialKeyMaterial,
            clientAuthKeyMaterial = clientAuthKeyMaterial,
            mockEngine = mockEngine,
            credentialIssuer = credentialIssuer,
            authorizationService = authorizationService,
            statusListIssuer = statusListIssuer,
            client = OpenId4VciClient(
                engine = mockEngine,
                oid4vciService = WalletService(
                    clientId = clientId,
                    keyMaterial = credentialKeyMaterial,
                ),
                oauth2Client = OAuth2KtorClient(
                    engine = mockEngine,
                    loadInstanceAttestation = { _ ->
                        catching {
                            BuildClientAttestationJwt(
                                SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                                clientId = clientId,
                                clientKey = clientAuthKeyMaterial.jsonWebKey
                            )
                        }
                    },
                    keyMaterial = clientAuthKeyMaterial,
                    oAuth2Client = OAuth2Client(clientId = clientId),
                    randomSource = RandomSource.Default,
                )
            )
        )
    }

    "loadEuPidCredentialSdJwt" {
        val expectedFamilyName = uuid4().toString()
        val expectedAttributeName = EuPidSdJwtDataElements.FAMILY_NAME
        val euPidSdJwtScheme = AttributeIndex.resolveIdentifier(EU_PID_SD_JWT_VCT, SD_JWT)
        with(setup(euPidSdJwtScheme, SD_JWT, mapOf(expectedAttributeName to expectedFamilyName))) {
            var refreshTokenStore: CredentialRenewalInfo? = null

            // Load credential identifier infos from Issuing service
            val credentialIdentifierInfos = client.loadCredentialMetadata("http://localhost").getOrThrow()
            // just pick the first credential in SD-JWT that is available
            val selectedCredential = credentialIdentifierInfos
                .first { it.supportedCredentialFormat.format == CredentialFormatEnum.DC_SD_JWT }

            client.startProvisioningWithAuthRequestReturningResult(
                credentialIssuerUrl = "http://localhost",
                credentialIdentifierInfo = selectedCredential,
            ).getOrThrow().also {
                // Simulates the browser, handling authorization to get the authCode
                val httpClient = HttpClient(mockEngine) { followRedirects = false }
                val authCode = httpClient.get(it.url).headers[HttpHeaders.Location]
                client.resumeWithAuthCode(authCode!!, it.context).getOrThrow().also {
                    refreshTokenStore = it.refreshToken!!
                    it.verifySdJwtCredential(
                        expectedAttributeName,
                        expectedFamilyName,
                        credentialKeyMaterial.publicKey
                    )
                }
            }

            refreshTokenStore.shouldNotBeNull()
            client.refreshCredentialReturningResult(refreshTokenStore).getOrThrow().also {
                it.verifySdJwtCredential(
                    expectedAttributeName,
                    expectedFamilyName,
                    credentialKeyMaterial.publicKey
                )
            }
        }
    }

    "loadEuPidCredentialIsoWithOfferIdentifierListRevocation" {
        val expectedAttributeValue = uuid4().toString()
        val expectedAttributeName = EuPidDataElements.GIVEN_NAME
        val euPidScheme = AttributeIndex.resolveIdentifier(EU_PID_DOCTYPE, ISO_MDOC)
        with(
            setup(
                scheme = euPidScheme,
                representation = ISO_MDOC,
                attributes = mapOf(expectedAttributeName to expectedAttributeValue),
                revocationKind = RevocationList.Kind.IDENTIFIER_LIST,
            )
        ) {
            val credentialIdentifierInfos = client.loadCredentialMetadata("http://localhost").getOrThrow()
            val selectedCredential = credentialIdentifierInfos
                .first { it.supportedCredentialFormat.format == CredentialFormatEnum.MSO_MDOC }

            val offer = authorizationService.offerWithPreAuthnForUserForSchemes(
                user = dummyUser(),
                credentialIssuer = credentialIssuer.metadata.credentialIssuer,
                schemes = setOf(euPidScheme to ISO_MDOC),
            )
            val issuedCredential = client.loadCredentialWithOfferReturningResult(offer, selectedCredential, null)
                .getOrThrow()
                .shouldBeInstanceOf<CredentialIssuanceResult.Success>()
                .also { it.verifyIsoMdocCredential(expectedAttributeName, expectedAttributeValue) }
                .credentials.first().shouldBeInstanceOf<Holder.StoreCredentialInput.Iso>()

            val statusInfo = issuedCredential.issuerSigned.issuerAuth.payload.shouldNotBeNull()
                .status.shouldNotBeNull().shouldBeInstanceOf<IdentifierListInfo>()

            val tokenStatusResolver = TokenStatusResolverImpl(
                resolveStatusListToken = { _ ->
                    StatusListCwt(
                        value = statusListIssuer.issueStatusListCwt(kind = RevocationList.Kind.IDENTIFIER_LIST),
                        resolvedAt = null,
                    )
                }
            )

            tokenStatusResolver(statusInfo).getOrThrow() shouldBe TokenStatus.Valid
            statusListIssuer.revokeCredentialByIdentifier(
                FixedTimePeriodProvider.timePeriod,
                statusInfo.identifier
            ) shouldBe true
            tokenStatusResolver(statusInfo).getOrThrow() shouldBe TokenStatus.Invalid
        }
    }

    "loadEuPidCredentialIsoWithOffer" {
        val expectedAttributeValue = uuid4().toString()
        val expectedAttributeName = EuPidDataElements.GIVEN_NAME
        val euPidScheme = AttributeIndex.resolveIdentifier(EU_PID_DOCTYPE, ISO_MDOC)
        with(setup(euPidScheme, ISO_MDOC, mapOf(expectedAttributeName to expectedAttributeValue))) {
            var refreshTokenStore: CredentialRenewalInfo? = null
            // Load credential identifier infos from Issuing service
            val credentialIdentifierInfos = client.loadCredentialMetadata("http://localhost").getOrThrow()
            // just pick the first credential in MSO_MDOC that is available
            val selectedCredential = credentialIdentifierInfos
                .first { it.supportedCredentialFormat.format == CredentialFormatEnum.MSO_MDOC }

            val offer = authorizationService.offerWithPreAuthnForUserForSchemes(
                user = dummyUser(),
                credentialIssuer = credentialIssuer.metadata.credentialIssuer,
                schemes = setOf(euPidScheme to ISO_MDOC),
            )
            client.loadCredentialWithOfferReturningResult(offer, selectedCredential, null).getOrThrow().also {
                it.shouldBeInstanceOf<CredentialIssuanceResult.Success>().also {
                    refreshTokenStore = it.refreshToken!!
                    it.verifyIsoMdocCredential(expectedAttributeName, expectedAttributeValue)
                }
            }
            refreshTokenStore.shouldNotBeNull()
            client.refreshCredentialReturningResult(refreshTokenStore).getOrThrow().also {
                it.verifyIsoMdocCredential(expectedAttributeName, expectedAttributeValue)
            }
        }
    }
}
