package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.*
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2DataProvider
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.oidvci.WalletService.RequestOptions
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.DOCUMENT_NUMBER
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
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
            credentialSchemes = setOf(AtomicAttribute2023),
            credentialProvider = DummyOAuth2IssuerCredentialDataProvider,
        )
        client = WalletService()
        state = uuid4().toString()
    }

    suspend fun getToken(scope: String?): TokenResponseParameters {
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
            scope = scope,
            resource = issuer.metadata.credentialIssuer
        )
        return authorizationService.token(tokenRequest).getOrThrow()
    }

    suspend fun getToken(authorizationDetails: Set<AuthorizationDetails>): TokenResponseParameters {
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
            authorizationDetails = authorizationDetails
        )
        return authorizationService.token(tokenRequest).getOrThrow()
    }

    suspend fun issueCredential(
        requestOptions: RequestOptions,
        token: TokenResponseParameters
    ): CredentialResponseParameters {
        val credentialRequest = client.createCredentialRequest(
            input = WalletService.CredentialRequestInput.RequestOptions(requestOptions),
            clientNonce = token.clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer
        ).getOrThrow()
        return issuer.credential(token.accessToken, credentialRequest).getOrThrow()
    }

    suspend fun issueCredential(
        credentialIdentifier: String,
        token: TokenResponseParameters
    ): CredentialResponseParameters {
        val credentialRequest = client.createCredentialRequest(
            input = WalletService.CredentialRequestInput.CredentialIdentifier(credentialIdentifier),
            clientNonce = token.clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer
        ).getOrThrow()
        return issuer.credential(token.accessToken, credentialRequest).getOrThrow()
    }

    fun defectMapStore() = object : MapStore<String, OidcUserInfoExtended> {
        override suspend fun put(key: String, value: OidcUserInfoExtended) = Unit
        override suspend fun get(key: String): OidcUserInfoExtended? = null
        override suspend fun remove(key: String): OidcUserInfoExtended? = null
    }

    "request one credential, using scope" {
        val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
        val scope = client.buildScope(requestOptions, issuer.metadata)
        val token = getToken(scope)
        val credential = issueCredential(requestOptions, token)
        credential.format shouldBe CredentialFormatEnum.JWT_VC
        val serializedCredential = credential.credential.shouldNotBeNull()

        JwsSigned.deserialize<VerifiableCredentialJws>(VerifiableCredentialJws.serializer(), serializedCredential, vckJsonSerializer).getOrThrow()
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
            issueCredential(it.value, token).credential.shouldNotBeNull()
        }
    }

    "proof over different keys leads to an error" {
        val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
        val scope = client.buildScope(requestOptions, issuer.metadata)
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
        val scope = client.buildScope(requestOptions, issuer.metadata)

        shouldThrow<OAuth2Exception> {
            getToken(scope)
        }
    }

    "request credential in SD-JWT, using scope" {
        val requestOptions = RequestOptions(AtomicAttribute2023, SD_JWT)
        val scope = client.buildScope(requestOptions, issuer.metadata)
        val token = getToken(scope)

        val credential = issueCredential(requestOptions, token)
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credential.shouldNotBeNull()

        val sdJwt = JwsSigned.deserialize<VerifiableCredentialSdJwt>(VerifiableCredentialSdJwt.serializer(), serializedCredential.substringBefore("~"))
            .getOrThrow().payload

        sdJwt.disclosureDigests
            .shouldNotBeNull()
            .size shouldBeGreaterThan 1
    }

    "request credential in SD-JWT, using authorization details" {
        val credentialIdToRequest = AtomicAttribute2023.toCredentialIdentifier(SD_JWT)
        val authorizationDetails = client.buildAuthorizationDetails(
            credentialConfigurationId = credentialIdToRequest,
            authorizationServers = issuer.metadata.authorizationServers
        )
        val token = getToken(authorizationDetails)

        val credential = issueCredential(credentialIdToRequest, token)
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credential.shouldNotBeNull()

        val sdJwt = JwsSigned.deserialize<VerifiableCredentialSdJwt>(VerifiableCredentialSdJwt.serializer(), serializedCredential.substringBefore("~"))
            .getOrThrow().payload

        sdJwt.disclosureDigests
            .shouldNotBeNull()
            .size shouldBeGreaterThan 1
    }

    "request credential in SD-JWT with just one claim, using scope" {
        val requestOptions = RequestOptions(AtomicAttribute2023, SD_JWT, setOf(CLAIM_FAMILY_NAME))
        val scope = client.buildScope(requestOptions, issuer.metadata)
        val token = getToken(scope)

        val credential = issueCredential(requestOptions, token)
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credential.shouldNotBeNull()

        val sdJwt = JwsSigned.deserialize<VerifiableCredentialSdJwt>(VerifiableCredentialSdJwt.serializer(), serializedCredential.substringBefore("~"))
            .getOrThrow().payload

        sdJwt.disclosureDigests
            .shouldNotBeNull()
            .size shouldBe 1
    }

    "request credential in ISO MDOC, using scope" {
        val requestOptions = RequestOptions(MobileDrivingLicenceScheme, ISO_MDOC)
        val scope = client.buildScope(requestOptions, issuer.metadata)
        val token = getToken(scope)

        val credential = issueCredential(requestOptions, token)
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        val serializedCredential = credential.credential.shouldNotBeNull()

        val issuerSigned = IssuerSigned.deserialize(serializedCredential.decodeToByteArray(Base64())).getOrThrow()

        val namespaces = issuerSigned.namespaces
            .shouldNotBeNull()

        namespaces.keys.first() shouldBe MobileDrivingLicenceScheme.isoNamespace
        val numberOfClaims = namespaces.values.firstOrNull()?.entries?.size.shouldNotBeNull()
        numberOfClaims shouldBeGreaterThan 1
    }

    "request credential in ISO MDOC with just one claim, using scope" {
        val requestOptions = RequestOptions(MobileDrivingLicenceScheme, ISO_MDOC, setOf(DOCUMENT_NUMBER))
        val scope = client.buildScope(requestOptions, issuer.metadata)
        val token = getToken(scope)
        val credential = issueCredential(requestOptions, token)
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        val serializedCredential = credential.credential.shouldNotBeNull()

        val issuerSigned = IssuerSigned.deserialize(serializedCredential.decodeToByteArray(Base64())).getOrThrow()

        val namespaces = issuerSigned.namespaces
        namespaces.shouldNotBeNull()
        namespaces.keys.first() shouldBe MobileDrivingLicenceScheme.isoNamespace
        val numberOfClaims = namespaces.values.firstOrNull()?.entries?.size.shouldNotBeNull()
        numberOfClaims shouldBe 1
    }

})
