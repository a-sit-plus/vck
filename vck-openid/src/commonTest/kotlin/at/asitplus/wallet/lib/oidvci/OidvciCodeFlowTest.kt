package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.*
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.oauth2.IssuedCode
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.WalletService.RequestOptions
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2DataProvider
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

class OidvciCodeFlowTest : FreeSpec({

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
            credentialProvider = DummyOAuth2IssuerCredentialDataProvider,
        )
        client = WalletService()
        state = uuid4().toString()
    }

    suspend fun getToken(scope: String, setScopeInTokenRequest: Boolean = true): TokenResponseParameters {
        val authnRequest = client.oauth2Client.createAuthRequest(
            state = state,
            scope = scope,
            resource = issuer.metadata.credentialIssuer
        )
        val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            scope = if (setScopeInTokenRequest) scope else null,
            resource = issuer.metadata.credentialIssuer
        )
        return authorizationService.token(tokenRequest).getOrThrow()
    }

    suspend fun getToken(
        authorizationDetails: Set<AuthorizationDetails>,
        setAuthnDetailsInTokenRequest: Boolean = true,
    ): TokenResponseParameters {
        val authnRequest = client.oauth2Client.createAuthRequest(
            state = state,
            authorizationDetails = authorizationDetails
        )
        val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            authorizationDetails = if (setAuthnDetailsInTokenRequest) authorizationDetails else null,
        )
        return authorizationService.token(tokenRequest).getOrThrow()
    }

    fun defectMapStore() = object : MapStore<String, IssuedCode> {
        override suspend fun put(key: String, value: IssuedCode) = Unit
        override suspend fun get(key: String): IssuedCode? = null
        override suspend fun remove(key: String): IssuedCode? = null
    }

    "request one credential, using scope" {
        val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
        val scope = client.buildScope(requestOptions, issuer.metadata).shouldNotBeNull()
        val token = getToken(scope)
        val credential = issuer.credential(
            token.accessToken, client.createCredentialRequest(
                tokenResponse = token,
                metadata = issuer.metadata
            ).getOrThrow().first()
        ).getOrThrow()
        credential.format shouldBe CredentialFormatEnum.JWT_VC
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
            client.buildScope(it, issuer.metadata)!!
        }
        val scope = requestOptions.keys.joinToString(" ")
        val token = getToken(scope)

        requestOptions.forEach {
            issuer.credential(
                token.accessToken,
                client.createCredentialRequest(
                    tokenResponse = token,
                    metadata = issuer.metadata
                ).getOrThrow().first()
            ).getOrThrow().credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()
        }
    }

    "proof over different keys leads to an error" {
        val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
        val scope = client.buildScope(requestOptions, issuer.metadata).shouldNotBeNull()
        val token = getToken(scope)
        val proof = client.createCredentialRequestProof(
            clientNonce = token.clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer,
            clock = requestOptions.clock
        )
        val differentProof = WalletService().createCredentialRequestProof(
            clientNonce = token.clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer,
            clock = requestOptions.clock
        )
        val credentialRequest = CredentialRequestParameters(
            format = CredentialFormatEnum.JWT_VC,
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = setOf(VERIFIABLE_CREDENTIAL, AtomicAttribute2023.vcType),
            ),
            proofs = CredentialRequestProofContainer(
                proofType = OpenIdConstants.ProofType.JWT,
                jwt = setOf(proof.jwt!!, differentProof.jwt!!)
            )
        )

        issuer.credential(token.accessToken, credentialRequest)
            .exceptionOrNull().shouldBeInstanceOf<OAuth2Exception>()
    }

    "authorizationService with defect mapstore leads to an error" {
        authorizationService = SimpleAuthorizationService(
            codeToUserInfoStore = defectMapStore(),
            strategy = CredentialAuthorizationServiceStrategy(
                DummyOAuth2DataProvider,
                setOf(AtomicAttribute2023)
            ),
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(),
            credentialSchemes = setOf(AtomicAttribute2023),
            credentialProvider = DummyOAuth2IssuerCredentialDataProvider
        )
        val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
        val scope = client.buildScope(requestOptions, issuer.metadata).shouldNotBeNull()

        shouldThrow<OAuth2Exception> {
            getToken(scope)
        }
    }

    "request credential in SD-JWT, using scope" {
        val requestOptions = RequestOptions(AtomicAttribute2023, SD_JWT)
        val scope = client.buildScope(requestOptions, issuer.metadata).shouldNotBeNull()
        val token = getToken(scope)

        val credential = issuer.credential(
            token.accessToken,
            client.createCredentialRequest(
                tokenResponse = token,
                metadata = issuer.metadata
            ).getOrThrow().first()
        ).getOrThrow()
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()

        serializedCredential.assertSdJwtReceived()
    }

    "request credential in SD-JWT, using scope only in authn request" {
        val requestOptions = RequestOptions(AtomicAttribute2023, SD_JWT)
        val scope = client.buildScope(requestOptions, issuer.metadata).shouldNotBeNull()
        val token = getToken(scope, false) // do not set scope in token request, only in authn request

        val credential = issuer.credential(
            token.accessToken,
            client.createCredentialRequest(
                tokenResponse = token,
                metadata = issuer.metadata
            ).getOrThrow().first()
        ).getOrThrow()
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()

        serializedCredential.assertSdJwtReceived()
    }

    "request credential in SD-JWT, using scope in access token different to auth code" {
        val authCodeScope = client.buildScope(RequestOptions(AtomicAttribute2023, SD_JWT), issuer.metadata)
            .shouldNotBeNull()
        val tokenScope = client.buildScope(RequestOptions(AtomicAttribute2023, ISO_MDOC), issuer.metadata)
            .shouldNotBeNull()
        val authnRequest = client.oauth2Client.createAuthRequest(
            state = state,
            scope = authCodeScope,
            resource = issuer.metadata.credentialIssuer
        )
        val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            scope = tokenScope, // this is wrong, should be the same as in authn request
            resource = issuer.metadata.credentialIssuer
        )
        shouldThrow<OAuth2Exception> {
            authorizationService.token(tokenRequest).getOrThrow()
        }
    }

    "request credential in SD-JWT, using authorization details" {
        val authorizationDetails = client.buildAuthorizationDetails(
            credentialConfigurationId = AtomicAttribute2023.toCredentialIdentifier(SD_JWT),
            authorizationServers = issuer.metadata.authorizationServers
        )
        val token = getToken(authorizationDetails)

        val credential = issuer.credential(
            token.accessToken,
            client.createCredentialRequest(
                tokenResponse = token,
                metadata = issuer.metadata
            ).getOrThrow().first()
        ).getOrThrow()
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()

        serializedCredential.assertSdJwtReceived()
    }

    "request credential in SD-JWT, using authorization details only in authnrequest" {
        val authorizationDetails = client.buildAuthorizationDetails(
            credentialConfigurationId = AtomicAttribute2023.toCredentialIdentifier(SD_JWT),
            authorizationServers = issuer.metadata.authorizationServers
        )
        val token = getToken(authorizationDetails, false) // do not set authn details in token request

        val credential = issuer.credential(
            token.accessToken,
            client.createCredentialRequest(
                tokenResponse = token,
                metadata = issuer.metadata
            ).getOrThrow().first()
        ).getOrThrow()
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
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
        val authnRequest = client.oauth2Client.createAuthRequest(
            state = state,
            authorizationDetails = authCodeAuthnDetails
        )
        val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            authorizationDetails = tokenAuthnDetails // this is wrong, should be same as in authn request
        )
        shouldThrow<OAuth2Exception> {
            authorizationService.token(tokenRequest).getOrThrow()
        }
    }

    "request credential in SD-JWT, using scope in token, but authorization details in credential request" {
        val scope = client.buildScope(RequestOptions(AtomicAttribute2023, SD_JWT), issuer.metadata)
            .shouldNotBeNull()
        val token = getToken(scope)

        shouldThrow<OAuth2Exception> {
            issuer.credential(
                token.accessToken,
                client.createCredentialRequest(
                    tokenResponse = token,
                    metadata = issuer.metadata
                ).getOrThrow().first().copy(
                    // enforces error on client, setting credential_identifier, although access token was for scope
                    // (which should be credential_configuration_id in credential request)
                    credentialIdentifier = AtomicAttribute2023.toCredentialIdentifier(SD_JWT),
                    credentialConfigurationId = null,
                )
            ).getOrThrow()
        }
    }

    "request credential in SD-JWT, using authorization details in token, but scope in credential request" {
        val scope = client.buildScope(RequestOptions(AtomicAttribute2023, SD_JWT), issuer.metadata).shouldNotBeNull()
        val authorizationDetails = client.buildAuthorizationDetails(
            credentialConfigurationId = AtomicAttribute2023.toCredentialIdentifier(SD_JWT),
            authorizationServers = issuer.metadata.authorizationServers
        )
        val token = getToken(authorizationDetails)

        shouldThrow<OAuth2Exception> {
            issuer.credential(
                token.accessToken,
                client.createCredentialRequest(
                    tokenResponse = token,
                    metadata = issuer.metadata
                ).getOrThrow().first().copy(
                    // enforces error on client, setting credential_configuration_id, although access token was for
                    // authorization details (which should be credential_identifier in credential request)
                    credentialConfigurationId = scope,
                    credentialIdentifier = null
                )
            ).getOrThrow()
        }
    }

    "request credential in ISO MDOC, using scope" {
        val requestOptions = RequestOptions(MobileDrivingLicenceScheme, ISO_MDOC)
        val scope = client.buildScope(requestOptions, issuer.metadata).shouldNotBeNull()
        val token = getToken(scope)

        val credential = issuer.credential(
            token.accessToken, client.createCredentialRequest(
                tokenResponse = token,
                metadata = issuer.metadata
            ).getOrThrow().first()
        ).getOrThrow()
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        val serializedCredential = credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull()

        val issuerSigned = IssuerSigned.deserialize(serializedCredential.decodeToByteArray(Base64())).getOrThrow()

        val namespaces = issuerSigned.namespaces
            .shouldNotBeNull()

        namespaces.keys.first() shouldBe MobileDrivingLicenceScheme.isoNamespace
        val numberOfClaims = namespaces.values.firstOrNull()?.entries?.size.shouldNotBeNull()
        numberOfClaims shouldBeGreaterThan 1
    }

})

private fun String.assertSdJwtReceived() {
    JwsSigned.deserialize(
        VerifiableCredentialSdJwt.serializer(),
        substringBefore("~")
    ).getOrThrow().payload.disclosureDigests
        .shouldNotBeNull()
        .size shouldBeGreaterThan 1
}
