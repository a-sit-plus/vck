package at.asitplus.wallet.lib.oidvci

import at.asitplus.catching
import at.asitplus.iso.IssuerSigned
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialRequestProofContainer
import at.asitplus.openid.CredentialResponseSingleCredential
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oauth2.AuthorizationServiceStrategy
import at.asitplus.wallet.lib.oauth2.ClientAuthRequest
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.CredentialSchemeMapping.toCredentialIdentifier
import at.asitplus.wallet.lib.oidvci.WalletService.RequestOptions
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.openid.DummyUserProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import at.asitplus.testballoon.*
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.maps.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.decodeFromByteArray

class OidvciCodeFlowTest by testSuite{

    lateinit var strategy: AuthorizationServiceStrategy
    lateinit var authorizationService: SimpleAuthorizationService
    lateinit var issuer: CredentialIssuer
    lateinit var client: WalletService
    lateinit var state: String

    beforeEach {
        strategy = CredentialAuthorizationServiceStrategy(setOf(AtomicAttribute2023, MobileDrivingLicenceScheme))
        authorizationService = SimpleAuthorizationService(
            strategy = strategy,
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(
                identifier = "https://issuer.example.com".toUri(),
                randomSource = RandomSource.Default
            ),
            credentialSchemes = setOf(AtomicAttribute2023, MobileDrivingLicenceScheme),
        )
        client = WalletService()
        state = uuid4().toString()
    }

    suspend fun getToken(scope: String, setScopeInTokenRequest: Boolean = true): TokenResponseParameters {
        val authnRequest = client.oauth2Client.createAuthRequestJar(
            state = state,
            scope = scope,
            resource = issuer.metadata.credentialIssuer
        )
        val input = authnRequest as RequestParameters
        val authnResponse = authorizationService.authorize(input) { catching { DummyUserProvider.user } }
            .getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params?.code
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            scope = if (setScopeInTokenRequest) scope else null,
            resource = issuer.metadata.credentialIssuer
        )
        return authorizationService.token(tokenRequest, null).getOrThrow()
    }

    suspend fun getToken(
        service: SimpleAuthorizationService,
        authorizationDetails: Set<AuthorizationDetails>,
        setAuthnDetailsInTokenRequest: Boolean = true,
    ): TokenResponseParameters {
        val authnRequest = client.oauth2Client.createAuthRequestJar(
            state = state,
            authorizationDetails = authorizationDetails
        )
        val input = authnRequest as RequestParameters
        val authnResponse = service.authorize(input) { catching { DummyUserProvider.user } }
            .getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params?.code
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            authorizationDetails = if (setAuthnDetailsInTokenRequest) authorizationDetails else null,
        )
        return service.token(tokenRequest, null).getOrThrow()
    }

    fun defectMapStore() = object : MapStore<String, ClientAuthRequest> {
        override suspend fun put(key: String, value: ClientAuthRequest) = Unit
        override suspend fun get(key: String): ClientAuthRequest? = null
        override suspend fun remove(key: String): ClientAuthRequest? = null
    }

    "metadata validation" {
        val issuerCredentialFormats = issuer.metadata.supportedCredentialConfigurations.shouldNotBeNull()
        issuerCredentialFormats.shouldNotBeEmpty()
        issuerCredentialFormats.forEach { it: Map.Entry<String, SupportedCredentialFormat> ->
            it.key.shouldNotBeEmpty()
            it.value.shouldNotBeNull().also {
                it.format.shouldNotBeNull()
                it.scope.shouldNotBeEmpty()
                it.supportedSigningAlgorithms.shouldNotBeNull().shouldNotBeEmpty()
                it.supportedProofTypes.shouldNotBeNull().shouldNotBeEmpty()
                it.supportedBindingMethods.shouldNotBeNull().shouldNotBeEmpty()
                if (it.format != CredentialFormatEnum.JWT_VC) {
                    it.claimDescription.shouldNotBeNull().shouldNotBeEmpty()
                    it.credentialMetadata.shouldNotBeNull().claimDescription.shouldNotBeNull().shouldNotBeEmpty()
                }
            }
        }
        strategy.validAuthorizationDetails().shouldNotBeEmpty().forEach {
            it.shouldBeInstanceOf<OpenIdAuthorizationDetails>()
                .credentialConfigurationId.shouldNotBeEmpty()
                .shouldBeIn(issuerCredentialFormats.keys)
        }
    }

    "request one credential, using scope" {
        val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope)
        val credential = issuer.credential(
            authorizationHeader = token.toHttpHeaderValue(),
            params = client.createCredential(
                tokenResponse = token,
                metadata = issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().first(),
            credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
        ).getOrThrow()
        val serializedCredential = credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()

        JwsSigned.deserialize<VerifiableCredentialJws>(
            VerifiableCredentialJws.serializer(),
            serializedCredential,
            vckJsonSerializer
        ).getOrThrow()
            .payload.vc.credentialSubject.shouldBeInstanceOf<at.asitplus.wallet.lib.data.AtomicAttribute2023>()
    }

    "request multiple credentials, using scope" {
        val requestOptions = setOf(
            RequestOptions(AtomicAttribute2023, SD_JWT),
            RequestOptions(AtomicAttribute2023, ISO_MDOC),
        ).associateBy {
            client.selectSupportedCredentialFormat(it, issuer.metadata)!!
        }
        val scope = requestOptions.keys.joinToString(" ") { it.scope.shouldNotBeNull() }
        val token = getToken(scope)

        requestOptions.forEach {
            issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = client.createCredential(
                    tokenResponse = token,
                    metadata = issuer.metadata,
                    credentialFormat = it.key,
                    clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                ).getOrThrow().first(),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow().credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()
        }
    }

    "proof over different keys leads to different credentials" {
        val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
        val scope = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata)?.scope.shouldNotBeNull()
        val clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce
        val token = getToken(scope)
        val proof = client.createCredentialRequestProofJwt(
            clientNonce = clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer,
        )
        val differentProof = WalletService().createCredentialRequestProofJwt(
            clientNonce = clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer,
        )
        val credentialRequest = CredentialRequestParameters(
            credentialConfigurationId = scope,
            proofs = CredentialRequestProofContainer(
                jwt = setOf(proof.jwt!!, differentProof.jwt!!)
            )
        )

        val credentials: Collection<CredentialResponseSingleCredential> =
            issuer.credential(
                token.toHttpHeaderValue(),
                credentialRequest,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .credentials.shouldNotBeEmpty().shouldHaveSize(2)
        // subject identifies the key of the client, here the keys of different proofs, so they should be unique
        credentials.map {
            JwsSigned.deserialize<VerifiableCredentialJws>(
                VerifiableCredentialJws.serializer(),
                it.credentialString.shouldNotBeNull(),
                vckJsonSerializer
            ).getOrThrow().payload.subject
        }.toSet().shouldHaveSize(2)
    }

    "authorizationService with defect mapstore leads to an error" {
        authorizationService = SimpleAuthorizationService(
            codeToClientAuthRequest = defectMapStore(),
            strategy = CredentialAuthorizationServiceStrategy(setOf(AtomicAttribute2023)),
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(
                identifier = "https://issuer.example.com".toUri(),
                randomSource = RandomSource.Default
            ),
            credentialSchemes = setOf(AtomicAttribute2023),
        )
        val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
        val scope = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata)?.scope.shouldNotBeNull()

        shouldThrow<OAuth2Exception> {
            getToken(scope)
        }
    }

    "request credential in SD-JWT, using scope" {
        val requestOptions = RequestOptions(AtomicAttribute2023, SD_JWT)
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope)

        val credential = issuer.credential(
            authorizationHeader = token.toHttpHeaderValue(),
            params = client.createCredential(
                tokenResponse = token,
                metadata = issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().first(),
            credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
        ).getOrThrow()
        val serializedCredential = credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()

        serializedCredential.assertSdJwtReceived()
    }

    "request credential in SD-JWT, using scope only in authn request" {
        val requestOptions = RequestOptions(AtomicAttribute2023, SD_JWT)
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope, false) // do not set scope in token request, only in authn request

        val credential = issuer.credential(
            authorizationHeader = token.toHttpHeaderValue(),
            params = client.createCredential(
                tokenResponse = token,
                metadata = issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().first(),
            credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
        ).getOrThrow()
        val serializedCredential = credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()

        serializedCredential.assertSdJwtReceived()
    }

    "request credential in SD-JWT, using scope in access token different to auth code" {
        val authCodeScope =
            client.selectSupportedCredentialFormat(RequestOptions(AtomicAttribute2023, SD_JWT), issuer.metadata)
                ?.scope.shouldNotBeNull()
        val tokenScope =
            client.selectSupportedCredentialFormat(RequestOptions(AtomicAttribute2023, ISO_MDOC), issuer.metadata)
                ?.scope.shouldNotBeNull()
        val authnRequest = client.oauth2Client.createAuthRequestJar(
            state = state,
            scope = authCodeScope,
            resource = issuer.metadata.credentialIssuer
        )
        val input = authnRequest as RequestParameters
        val authnResponse = authorizationService.authorize(input) { catching { DummyUserProvider.user } }
            .getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params?.code
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            scope = tokenScope, // this is wrong, should be the same as in authn request
            resource = issuer.metadata.credentialIssuer
        )
        shouldThrow<OAuth2Exception> {
            authorizationService.token(tokenRequest, null).getOrThrow()
        }
    }

    "request credential in SD-JWT, using authorization details" {
        val credentialConfigurationId = AtomicAttribute2023.toCredentialIdentifier(SD_JWT)
        val authorizationDetails = client.buildAuthorizationDetails(
            credentialConfigurationId = credentialConfigurationId,
            authorizationServers = issuer.metadata.authorizationServers
        )
        val credentialFormat = issuer.metadata.supportedCredentialConfigurations
            .shouldNotBeNull()[credentialConfigurationId]
            .shouldNotBeNull()
        val token = getToken(authorizationService, authorizationDetails)

        val credential = issuer.credential(
            authorizationHeader = token.toHttpHeaderValue(),
            params = client.createCredential(
                tokenResponse = token,
                metadata = issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().first(),
            credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
        ).getOrThrow()
        val serializedCredential = credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()

        serializedCredential.assertSdJwtReceived()
    }

    "request credential in SD-JWT, using authorization details only in authnrequest" {
        val credentialConfigurationId = AtomicAttribute2023.toCredentialIdentifier(SD_JWT)
        val authorizationDetails = client.buildAuthorizationDetails(
            credentialConfigurationId = credentialConfigurationId,
            authorizationServers = issuer.metadata.authorizationServers
        )
        val credentialFormat = issuer.metadata.supportedCredentialConfigurations
            .shouldNotBeNull()[credentialConfigurationId]
            .shouldNotBeNull()
        val token =
            getToken(authorizationService, authorizationDetails, false) // do not set authn details in token request

        val credential = issuer.credential(
            authorizationHeader = token.toHttpHeaderValue(),
            params = client.createCredential(
                tokenResponse = token,
                metadata = issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().first(),
            credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
        ).getOrThrow()
        val serializedCredential = credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()

        serializedCredential.assertSdJwtReceived()
    }

    "request credential in SD-JWT, using authorization details is access token different to auth code" {
        val authCodeAuthnDetails = client.buildAuthorizationDetails(
            credentialConfigurationId = AtomicAttribute2023.toCredentialIdentifier(SD_JWT),
            authorizationServers = issuer.metadata.authorizationServers
        )
        val tokenAuthnDetails = client.buildAuthorizationDetails(
            credentialConfigurationId = AtomicAttribute2023.toCredentialIdentifier(ISO_MDOC),
            authorizationServers = issuer.metadata.authorizationServers
        )
        val authnRequest = client.oauth2Client.createAuthRequestJar(
            state = state,
            authorizationDetails = authCodeAuthnDetails
        )
        val input = authnRequest as RequestParameters
        val authnResponse = authorizationService.authorize(input) { catching { DummyUserProvider.user } }
            .getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params?.code
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            authorizationDetails = tokenAuthnDetails // this is wrong, should be same as in authn request
        )
        shouldThrow<OAuth2Exception> {
            authorizationService.token(tokenRequest, null).getOrThrow()
        }
    }

    "request credential with unknown configuration_id" {
        // that credential format (from which credential_configuration_id will be derived) is not known to our issuer
        val credentialFormat = with(
            CredentialIssuer(
                authorizationService = SimpleAuthorizationService(
                    strategy = CredentialAuthorizationServiceStrategy(setOf(EuPidScheme)),
                ),
                issuer = IssuerAgent(
                    identifier = "https://secondissuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(EuPidScheme),
            )
        ) {
            client.selectSupportedCredentialFormat(RequestOptions(EuPidScheme, SD_JWT), metadata)
        }

        val scope = credentialFormat
            ?.scope.shouldNotBeNull()
        val token = getToken(scope)

        shouldThrow<OAuth2Exception.UnknownCredentialConfiguration> {
            issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = client.createCredential(
                    tokenResponse = token,
                    metadata = issuer.metadata,
                    credentialFormat = credentialFormat,
                    clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                ).getOrThrow().first(),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
        }
    }

    "request credential in SD-JWT, using scope in token, but authorization details in credential request" {
        val credentialFormat =
            client.selectSupportedCredentialFormat(RequestOptions(AtomicAttribute2023, SD_JWT), issuer.metadata)
        val scope = credentialFormat
            ?.scope.shouldNotBeNull()
        val token = getToken(scope)

        val first = client.createCredential(
            tokenResponse = token,
            metadata = issuer.metadata,
            credentialFormat = credentialFormat,
            clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
        ).getOrThrow().first()
        shouldThrow<OAuth2Exception> {
            issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = first.wrongCredentialIdentifier(),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
        }
    }

    "request credential in SD-JWT, using authorization details in token, but scope in credential request" {
        val credentialFormat =
            client.selectSupportedCredentialFormat(RequestOptions(AtomicAttribute2023, SD_JWT), issuer.metadata)
                .shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val authorizationDetails = client.buildAuthorizationDetails(
            credentialConfigurationId = AtomicAttribute2023.toCredentialIdentifier(SD_JWT),
            authorizationServers = issuer.metadata.authorizationServers
        )
        val token = getToken(authorizationService, authorizationDetails)

        shouldThrow<OAuth2Exception> {
            issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = client.createCredential(
                    tokenResponse = token,
                    metadata = issuer.metadata,
                    credentialFormat = credentialFormat,
                    clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                ).getOrThrow().first().wrongCredentialConfigurationId(scope),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
        }
    }


    "request credential in ISO MDOC, using scope" {
        val requestOptions = RequestOptions(MobileDrivingLicenceScheme, ISO_MDOC)
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat?.scope.shouldNotBeNull()
        val token = getToken(scope)

        val credential = issuer.credential(
            authorizationHeader = token.toHttpHeaderValue(),
            params = client.createCredential(
                tokenResponse = token,
                metadata = issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().first(),
            credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
        ).getOrThrow()
        val serializedCredential = credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()

        val issuerSigned =
            coseCompliantSerializer.decodeFromByteArray<IssuerSigned>(serializedCredential.decodeToByteArray(Base64()))

        val namespaces = issuerSigned.namespaces
            .shouldNotBeNull()

        namespaces.keys.first() shouldBe MobileDrivingLicenceScheme.isoNamespace
        val numberOfClaims = namespaces.values.firstOrNull()?.entries?.size.shouldNotBeNull()
        numberOfClaims shouldBeGreaterThan 1
    }

}
private fun String.assertSdJwtReceived() {
    JwsSigned.deserialize(
        VerifiableCredentialSdJwt.serializer(),
        substringBefore("~")
    ).getOrThrow().payload.disclosureDigests
        .shouldNotBeNull()
        .size shouldBeGreaterThan 1
}

private fun WalletService.CredentialRequest.wrongCredentialIdentifier() = when (this) {
    is WalletService.CredentialRequest.Encrypted -> this
    is WalletService.CredentialRequest.Plain -> WalletService.CredentialRequest.Plain(
        this.request.copy(
            // enforces error on client, setting credential_identifier, although access token was for scope
            // (which should be credential_configuration_id in credential request)
            credentialIdentifier = AtomicAttribute2023.toCredentialIdentifier(SD_JWT),
            credentialConfigurationId = null,
        )
    )
}

private fun WalletService.CredentialRequest.wrongCredentialConfigurationId(scope: String) = when (this) {
    is WalletService.CredentialRequest.Encrypted -> this
    is WalletService.CredentialRequest.Plain -> WalletService.CredentialRequest.Plain(
        this.request.copy(
            // enforces error on client, setting credential_configuration_id, although access token was for
            // authorization details (which should be credential_identifier in credential request)
            credentialConfigurationId = scope,
            credentialIdentifier = null
        )
    )
}
