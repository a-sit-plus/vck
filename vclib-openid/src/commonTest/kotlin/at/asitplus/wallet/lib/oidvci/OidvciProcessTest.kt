package at.asitplus.wallet.lib.oidvci

import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.DummyOAuth2DataProvider
import at.asitplus.wallet.lib.oidc.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray


class OidvciProcessTest : FunSpec({

    val authorizationService = SimpleAuthorizationService(
        dataProvider = DummyOAuth2DataProvider,
        credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme)
    )
    val issuer = CredentialIssuer(
        authorizationService = authorizationService,
        issuer = IssuerAgent(),
        credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme),
        buildIssuerCredentialDataProviderOverride = ::DummyOAuth2IssuerCredentialDataProvider
    )

    test("process with W3C VC JWT") {
        val client = WalletService()
        val credential = runProcessWithJwtProof(
            authorizationService,
            issuer,
            client,
            WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
            )
        )
        credential.format shouldBe CredentialFormatEnum.JWT_VC
        val serializedCredential = credential.credential.shouldNotBeNull()

        val jws = JwsSigned.parse(serializedCredential).getOrThrow()
        val vcJws = VerifiableCredentialJws.deserialize(jws.payload.decodeToString()).getOrThrow()
        vcJws.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
    }

    test("process with W3C VC SD-JWT") {
        val client = WalletService()
        val credential = runProcessWithJwtProof(
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

    test("process with W3C VC SD-JWT one requested claim") {
        val client = WalletService()
        val credential = runProcessWithJwtProof(
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
        val client = WalletService()
        val credential = runProcessWithCwtProof(
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

        val numberOfClaims = issuerSigned.namespaces?.values?.firstOrNull()?.entries?.size.shouldNotBeNull()
        numberOfClaims shouldBeGreaterThan 1
    }

    test("process with ISO mobile driving licence one requested claim") {
        val client = WalletService()
        val credential = runProcessWithCwtProof(
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

        val numberOfClaims = issuerSigned.namespaces?.values?.firstOrNull()?.entries?.size.shouldNotBeNull()
        numberOfClaims shouldBe 1
    }

    test("process with ISO atomic attributes") {
        val client = WalletService()
        val credential = runProcessWithCwtProof(
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

private suspend fun runProcessWithJwtProof(
    authorizationService: SimpleAuthorizationService,
    issuer: CredentialIssuer,
    client: WalletService,
    requestOptions: WalletService.RequestOptions,
): CredentialResponseParameters {
    val token = runProcessGetToken(authorizationService, client, requestOptions)
    val credentialRequest = client.createCredentialRequestJwt(
        requestOptions,
        token.clientNonce,
        issuer.metadata.credentialIssuer
    ).getOrThrow()
    return issuer.credential(token.accessToken, credentialRequest).getOrThrow()
}

private suspend fun runProcessWithCwtProof(
    authorizationService: SimpleAuthorizationService,
    issuer: CredentialIssuer,
    client: WalletService,
    requestOptions: WalletService.RequestOptions,
): CredentialResponseParameters {
    val token = runProcessGetToken(authorizationService, client, requestOptions)
    val credentialRequest = client.createCredentialRequestCwt(
        requestOptions = requestOptions,
        clientNonce = token.clientNonce,
        credentialIssuer = issuer.metadata.credentialIssuer
    ).getOrThrow()
    return issuer.credential(token.accessToken, credentialRequest).getOrThrow()
}

private suspend fun runProcessGetToken(
    authorizationService: SimpleAuthorizationService,
    client: WalletService,
    requestOptions: WalletService.RequestOptions,
): TokenResponseParameters {
    val authnRequest = client.createAuthRequest(requestOptions)
    val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
    authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
    val code = authnResponse.params.code.shouldNotBeNull()
    val tokenRequest = client.createTokenRequestParameters(
        requestOptions = requestOptions,
        code = code,
    )
    val token = authorizationService.token(tokenRequest).getOrThrow()
    return token
}
