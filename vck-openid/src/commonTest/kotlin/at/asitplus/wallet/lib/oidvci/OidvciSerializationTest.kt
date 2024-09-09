package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.DummyOAuth2DataProvider
import at.asitplus.wallet.lib.oidc.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.oidc.DummyOAuth2IssuerCredentialDataProvider.Companion.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.oidc.DummyOAuth2IssuerCredentialDataProvider.Companion.CLAIM_PORTRAIT
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

class OidvciSerializationTest : FunSpec({

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
            keyMaterial = EphemeralKeyWithSelfSignedCert()
        )
    }

    test("process with W3C VC SD-JWT one requested claim") {
        val credential = runProcess(
            authorizationService,
            issuer,
            client,
            WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                requestedAttributes = setOf(CLAIM_PORTRAIT, CLAIM_GIVEN_NAME)
            )
        )
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credential.shouldNotBeNull()

        val sdJwt = SdJwtSigned.parse(serializedCredential).shouldNotBeNull()
        val disclosures = sdJwt.disclosures.entries
            .also { println(it) }
        disclosures.find { it.value.claimName == CLAIM_PORTRAIT }?.value?.claimValue.shouldBeInstanceOf<ByteArray>()
        disclosures.find { it.value.claimName == CLAIM_GIVEN_NAME }?.value?.claimValue.shouldBeInstanceOf<String>()
    }

    test("process with ISO atomic attributes") {
        val credential = runProcess(
            authorizationService,
            issuer,
            client,
            WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                requestedAttributes = setOf(CLAIM_PORTRAIT, CLAIM_GIVEN_NAME)
            )
        )
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        val serializedCredential = credential.credential.shouldNotBeNull()

        val issuerSigned = IssuerSigned.deserialize(serializedCredential.decodeToByteArray(Base64())).getOrThrow()
        val namespaces = issuerSigned.namespaces?.values
        namespaces.shouldNotBeNull()
        namespaces.shouldBeSingleton()
        val issuerSignedItems = namespaces.single().entries.map { it.value }
        issuerSignedItems.find { it.elementIdentifier == CLAIM_PORTRAIT }?.elementValue.shouldBeInstanceOf<ByteArray>()
        issuerSignedItems.find { it.elementIdentifier == CLAIM_GIVEN_NAME }?.elementValue.shouldBeInstanceOf<String>()
        val mso = issuerSigned.getIssuerAuthPayloadAsMso().shouldNotBeNull()
        val msoValues = mso.valueDigests.values
        msoValues.shouldBeSingleton()
        msoValues.single().entries.size shouldBe 2
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
