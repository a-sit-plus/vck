package at.asitplus.wallet.lib.oidvci

import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.DummyCredentialDataProvider
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier
import at.asitplus.wallet.lib.oidc.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.wallet.lib.oidc.OpenIdConstants.TOKEN_PREFIX_BEARER
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

class OidvciProcessTest : FunSpec({

    val dataProvider = DummyCredentialDataProvider()
    val issuer = IssuerService(
        issuer = IssuerAgent.newDefaultInstance(
            cryptoService = DefaultCryptoService(),
            dataProvider = dataProvider
        ),
        credentialSchemes = listOf(ConstantIndex.AtomicAttribute2023, ConstantIndex.MobileDrivingLicence2023)
    )

    test("process with W3C VC JWT") {
        val client = WalletService(
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        )
        val credential = runProcess(issuer, client)
        credential.format shouldBe CredentialFormatEnum.JWT_VC
        val serializedCredential = credential.credential
        serializedCredential.shouldNotBeNull().also { println(it) }

        val jws = JwsSigned.parse(serializedCredential)
        jws.shouldNotBeNull()
        val vcJws = VerifiableCredentialJws.deserialize(jws.payload.decodeToString())
        vcJws.shouldNotBeNull().also { println(it) }
    }

    test("process with W3C VC SD-JWT") {
        val client = WalletService(
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.SD_JWT,
        )
        val credential = runProcess(issuer, client)
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credential
        serializedCredential.shouldNotBeNull().also { println(it) }

        val jws = JwsSigned.parse(serializedCredential)
        jws.shouldNotBeNull()
        val sdJwt = VerifiableCredentialSdJwt.deserialize(jws.payload.decodeToString())
        sdJwt.shouldNotBeNull().also { println(it) }
        sdJwt.disclosureDigests.size shouldBeGreaterThan 1
    }

    test("process with W3C VC SD-JWT one requested claim") {
        val client = WalletService(
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.SD_JWT,
            requestedAttributes = listOf("family-name")
        )
        val credential = runProcess(issuer, client)
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val serializedCredential = credential.credential
        serializedCredential.shouldNotBeNull().also { println(it) }

        val jws = JwsSigned.parse(serializedCredential)
        jws.shouldNotBeNull()
        val sdJwt = VerifiableCredentialSdJwt.deserialize(jws.payload.decodeToString())
        sdJwt.shouldNotBeNull().also { println(it) }
        sdJwt.disclosureDigests.size shouldBe 1
    }

    test("process with ISO mobile driving licence") {
        val client = WalletService(
            credentialScheme = ConstantIndex.MobileDrivingLicence2023,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
        )
        val credential = runProcess(issuer, client)
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        val serializedCredential = credential.credential
        serializedCredential.shouldNotBeNull().also { println(it) }

        val issuerSigned = IssuerSigned.deserialize(serializedCredential.decodeToByteArray(Base64()))
        issuerSigned.shouldNotBeNull().also { println(it) }
        val numberOfClaims = issuerSigned.namespaces?.values?.firstOrNull()?.entries?.size
        numberOfClaims.shouldNotBeNull()
        numberOfClaims shouldBeGreaterThan 1
    }

    test("process with ISO mobile driving licence one requested claim") {
        val client = WalletService(
            credentialScheme = ConstantIndex.MobileDrivingLicence2023,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
            requestedAttributes = listOf(MobileDrivingLicenceDataElements.DOCUMENT_NUMBER)
        )
        val credential = runProcess(issuer, client)
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        val serializedCredential = credential.credential
        serializedCredential.shouldNotBeNull().also { println(it) }

        val issuerSigned = IssuerSigned.deserialize(serializedCredential.decodeToByteArray(Base64()))
        issuerSigned.shouldNotBeNull().also { println(it) }
        val numberOfClaims = issuerSigned.namespaces?.values?.firstOrNull()?.entries?.size
        numberOfClaims.shouldNotBeNull()
        numberOfClaims shouldBe 1
    }

    test("process with ISO atomic attributes") {
        val client = WalletService(
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
        )
        val credential = runProcess(issuer, client)
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        val serializedCredential = credential.credential
        serializedCredential.shouldNotBeNull().also { println(it) }

        val issuerSigned = IssuerSigned.deserialize(serializedCredential.decodeToByteArray(Base64()))
        issuerSigned.shouldNotBeNull().also { println(it) }
    }

})

private suspend fun runProcess(
    issuer: IssuerService,
    client: WalletService
): CredentialResponseParameters {
    val metadata = issuer.metadata
    val authnRequest = client.createAuthRequest()
    val authnResponse = issuer.authorize(authnRequest)
    authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
    val code = authnResponse.params.code
    code.shouldNotBeNull()
    val tokenRequest = client.createTokenRequestParameters(authnResponse.params)
    val token = issuer.token(tokenRequest)
    val credentialRequest = client.createCredentialRequest(token, metadata).getOrThrow()
    return issuer.credential(TOKEN_PREFIX_BEARER + token.accessToken, credentialRequest)
}
