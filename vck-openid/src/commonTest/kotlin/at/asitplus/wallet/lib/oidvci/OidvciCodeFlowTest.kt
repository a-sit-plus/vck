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
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.DummyOAuth2DataProvider
import at.asitplus.wallet.lib.oidc.DummyOAuth2IssuerCredentialDataProvider
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

    suspend fun issueCredential(
        requestOptions: RequestOptions,
        token: TokenResponseParameters
    ): CredentialResponseParameters {
        val credentialRequest = client.createCredentialRequest(
            WalletService.CredentialRequestInput.RequestOptions(requestOptions),
            token.clientNonce,
            issuer.metadata.credentialIssuer
        ).getOrThrow()
        val credential = issuer.credential(token.accessToken, credentialRequest).getOrThrow()
        return credential
    }

    fun defectMapStore() = object : MapStore<String, OidcUserInfoExtended> {
        override suspend fun put(key: String, value: OidcUserInfoExtended) = Unit
        override suspend fun get(key: String): OidcUserInfoExtended? = null
        override suspend fun remove(key: String): OidcUserInfoExtended? = null
    }


    "process with W3C VC JWT" {
        val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
        val scope = client.buildScope(requestOptions, issuer.metadata)
        val token = getToken(scope)
        val credential = issueCredential(requestOptions, token)
        credential.format shouldBe CredentialFormatEnum.JWT_VC
        val serializedCredential = credential.credential.shouldNotBeNull()

        val jws = JwsSigned.deserialize(serializedCredential).getOrThrow()
        VerifiableCredentialJws.deserialize(jws.payload.decodeToString())
            .getOrThrow().vc.credentialSubject.shouldBeInstanceOf<at.asitplus.wallet.lib.data.AtomicAttribute2023>()
    }

    "process with request options for multiple credentials" {
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

    "process with W3C VC JWT, proof over different keys" {
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

    "process with W3C VC JWT, authorizationService with defect mapstore" {
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

    "process with W3C VC SD-JWT" {
        val requestOptions = RequestOptions(AtomicAttribute2023, SD_JWT)
        val scope = client.buildScope(requestOptions, issuer.metadata)
        val token = getToken(scope)

        val credential = issueCredential(requestOptions, token)
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credential.shouldNotBeNull()

        val jws = JwsSigned.deserialize(serializedCredential.substringBefore("~")).getOrThrow()
        val sdJwt = VerifiableCredentialSdJwt.deserialize(jws.payload.decodeToString()).getOrThrow()

        sdJwt.disclosureDigests
            .shouldNotBeNull()
            .size shouldBeGreaterThan 1
    }

    "process with W3C VC SD-JWT one requested claim" {
        val requestOptions = RequestOptions(AtomicAttribute2023, SD_JWT, setOf(CLAIM_FAMILY_NAME))
        val scope = client.buildScope(requestOptions, issuer.metadata)
        val token = getToken(scope)

        val credential = issueCredential(requestOptions, token)
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credential.shouldNotBeNull()

        val jws = JwsSigned.deserialize(serializedCredential.substringBeforeLast("~")).getOrThrow()
        val sdJwt = VerifiableCredentialSdJwt.deserialize(jws.payload.decodeToString()).getOrThrow()

        sdJwt.disclosureDigests
            .shouldNotBeNull()
            .size shouldBe 1
    }

    "process with ISO mobile driving licence" {
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

    "process with ISO mobile driving licence one requested claim" {
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
