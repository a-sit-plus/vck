package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.DummyOAuth2DataProvider
import at.asitplus.wallet.lib.oidc.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray


class OidvciProcessTest : FunSpec({

    lateinit var authorizationService: SimpleAuthorizationService
    lateinit var issuer: CredentialIssuer
    lateinit var client: WalletService

    beforeEach {
        authorizationService = SimpleAuthorizationService(
            dataProvider = DummyOAuth2DataProvider,
            credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023)
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(),
            credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
            buildIssuerCredentialDataProviderOverride = ::DummyOAuth2IssuerCredentialDataProvider
        )
        client = WalletService(
            clientId = "https://wallet.a-sit.at/app",
            redirectUrl = "https://wallet.a-sit.at/callback",
            keyPairAdapter = EphemeralKeyWithSelfSignedCert()
        )
    }

    test("process with W3C VC JWT") {
        val requestOptions = WalletService.RequestOptions(
            ConstantIndex.AtomicAttribute2023,
            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
        )
        val credential = runProcess(authorizationService, issuer, client, requestOptions)
        credential.format shouldBe CredentialFormatEnum.JWT_VC
        val serializedCredential = credential.credential.shouldNotBeNull()

        val jws = JwsSigned.parse(serializedCredential).getOrThrow()
        val vcJws = VerifiableCredentialJws.deserialize(jws.payload.decodeToString()).getOrThrow()
        vcJws.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
    }

    test("can't cash in token twice") {
        val requestOptions = WalletService.RequestOptions(
            ConstantIndex.AtomicAttribute2023,
            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
        )
        val authnRequest = client.createAuthRequest(requestOptions)
        val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code.shouldNotBeNull()
        val tokenRequest = client.createTokenRequestParameters(
            requestOptions = requestOptions,
            authorization = WalletService.AuthorizationForToken.Code(code)
        )
        authorizationService.token(tokenRequest).isSuccess shouldBe true
        authorizationService.token(tokenRequest).isFailure shouldBe true
    }

    test("process with W3C VC JWT, authorizationService with defect mapstore") {
        authorizationService = SimpleAuthorizationService(
            dataProvider = DummyOAuth2DataProvider,
            credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
            codeToUserInfoStore = object : MapStore<String, OidcUserInfoExtended> {
                override suspend fun put(key: String, value: OidcUserInfoExtended) = Unit
                override suspend fun get(key: String): OidcUserInfoExtended? = null
                override suspend fun remove(key: String): OidcUserInfoExtended? = null
            }
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(),
            credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
            buildIssuerCredentialDataProviderOverride = ::DummyOAuth2IssuerCredentialDataProvider
        )
        val requestOptions = WalletService.RequestOptions(
            ConstantIndex.AtomicAttribute2023,
            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
        )

        shouldThrow<OAuth2Exception> { runProcess(authorizationService, issuer, client, requestOptions) }
    }

    test("process with W3C VC SD-JWT") {
        val credential = runProcess(
            authorizationService,
            issuer,
            client,
            WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                representation = ConstantIndex.CredentialRepresentation.SD_JWT,
            )
        )
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credential.shouldNotBeNull()

        val jws = JwsSigned.parse(serializedCredential.substringBefore("~")).getOrThrow()
        val sdJwt = VerifiableCredentialSdJwt.deserialize(jws.payload.decodeToString()).getOrThrow()

        sdJwt.disclosureDigests.shouldNotBeNull()
        sdJwt.disclosureDigests!!.size shouldBeGreaterThan 1
    }

    test("process with W3C VC SD-JWT, credential offer, pre-authn") {
        val offer = issuer.credentialOffer()
            .also { println(it.serialize()) }
        val metadata = issuer.metadata
            .also { println(it.serialize()) }

        val selectedCredentialConfigurationId = "AtomicAttribute2023#vc+sd-jwt"
        val selectedCredential = metadata.supportedCredentialConfigurations!![selectedCredentialConfigurationId]!!
        val tokenRequest = client.createTokenRequestParameters(
            authorization = WalletService.AuthorizationForToken.PreAuthCode(offer.grants!!.preAuthorizedCode!!),
            credential = selectedCredential,
        ).also { println(it.serialize()) }
        val token = authorizationService.token(tokenRequest).getOrThrow()
            .also { println(it.serialize()) }
        val credentialRequest = client.createCredentialRequest(
            credential = selectedCredential,
            clientNonce = token.clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer
        ).getOrThrow()
            .also { println(it.serialize()) }
        val credential = issuer.credential(token.accessToken, credentialRequest).getOrThrow()
            .also { println(it.serialize()) }

        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credential.shouldNotBeNull()

        val jws = JwsSigned.parse(serializedCredential.substringBefore("~")).getOrThrow()
        val sdJwt = VerifiableCredentialSdJwt.deserialize(jws.payload.decodeToString()).getOrThrow()

        sdJwt.disclosureDigests.shouldNotBeNull()
        sdJwt.disclosureDigests!!.size shouldBeGreaterThan 1
    }

    test("process with W3C VC SD-JWT one requested claim") {
        val credential = runProcess(
            authorizationService,
            issuer,
            client,
            WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                requestedAttributes = setOf("family_name")
            )
        )
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credential.shouldNotBeNull()

        val jws = JwsSigned.parse(serializedCredential.substringBeforeLast("~")).getOrThrow()
        val sdJwt = VerifiableCredentialSdJwt.deserialize(jws.payload.decodeToString()).getOrThrow()

        sdJwt.disclosureDigests.shouldNotBeNull()
        sdJwt.disclosureDigests!!.size shouldBe 1
    }

    test("process with ISO mobile driving licence") {
        val credential = runProcess(
            authorizationService,
            issuer,
            client,
            WalletService.RequestOptions(
                MobileDrivingLicenceScheme,
                representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
            )
        )
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        val serializedCredential = credential.credential.shouldNotBeNull()

        val issuerSigned = IssuerSigned.deserialize(serializedCredential.decodeToByteArray(Base64())).getOrThrow()

        val namespaces = issuerSigned.namespaces
        namespaces.shouldNotBeNull()
        namespaces.keys.first() shouldBe MobileDrivingLicenceScheme.isoNamespace
        val numberOfClaims = namespaces.values.firstOrNull()?.entries?.size.shouldNotBeNull()
        numberOfClaims shouldBeGreaterThan 1
    }

    test("process with ISO mobile driving licence one requested claim") {
        val credential = runProcess(
            authorizationService,
            issuer,
            client,
            WalletService.RequestOptions(
                credentialScheme = MobileDrivingLicenceScheme,
                representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                requestedAttributes = setOf(MobileDrivingLicenceDataElements.DOCUMENT_NUMBER)
            )
        )
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        val serializedCredential = credential.credential.shouldNotBeNull()

        val issuerSigned = IssuerSigned.deserialize(serializedCredential.decodeToByteArray(Base64())).getOrThrow()

        val namespaces = issuerSigned.namespaces
        namespaces.shouldNotBeNull()
        namespaces.keys.first() shouldBe MobileDrivingLicenceScheme.isoNamespace
        val numberOfClaims = namespaces.values.firstOrNull()?.entries?.size.shouldNotBeNull()
        numberOfClaims shouldBe 1
    }

    test("process with ISO atomic attributes") {
        val credential = runProcess(
            authorizationService,
            issuer,
            client,
            WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                representation = ConstantIndex.CredentialRepresentation.ISO_MDOC
            )
        )
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        val serializedCredential = credential.credential.shouldNotBeNull()

        val issuerSigned = IssuerSigned.deserialize(serializedCredential.decodeToByteArray(Base64())).getOrThrow()
        val numberOfClaims = issuerSigned.namespaces?.values?.firstOrNull()?.entries?.size.shouldNotBeNull()
        numberOfClaims shouldBeGreaterThan 1
    }

})

private suspend fun runProcess(
    authorizationService: SimpleAuthorizationService,
    issuer: CredentialIssuer,
    client: WalletService,
    requestOptions: WalletService.RequestOptions,
): CredentialResponseParameters {
    val authnRequest = client.createAuthRequest(requestOptions)
    val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
    authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
    val code = authnResponse.params.code.shouldNotBeNull()
    val tokenRequest = client.createTokenRequestParameters(
        requestOptions = requestOptions,
        authorization = WalletService.AuthorizationForToken.Code(code)
    )
    val token = authorizationService.token(tokenRequest).getOrThrow()
    val credentialRequest = client.createCredentialRequest(
        requestOptions,
        token.clientNonce,
        issuer.metadata.credentialIssuer
    ).getOrThrow()
    return issuer.credential(token.accessToken, credentialRequest).getOrThrow()
}

