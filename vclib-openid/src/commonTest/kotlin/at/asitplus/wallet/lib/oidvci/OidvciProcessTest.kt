package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.jws.JwsSigned
import at.asitplus.wallet.lib.oidc.DummyCredentialDataProvider
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants.GRANT_TYPE_CODE
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.http.Url
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
        credential.credential.shouldNotBeNull()
        println(credential.credential)

        val jws = JwsSigned.parse(credential.credential!!)
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
        credential.format shouldBe CredentialFormatEnum.JWT_VC_SD
        credential.credential.shouldNotBeNull()
        println(credential.credential)

        val jws = JwsSigned.parse(credential.credential!!)
        jws.shouldNotBeNull()
        val sdJwt = VerifiableCredentialSdJwt.deserialize(jws.payload.decodeToString())
        sdJwt.shouldNotBeNull().also { println(it) }
    }

    test("process with ISO mobile driving licence") {
        val client = WalletService(
            credentialScheme = ConstantIndex.MobileDrivingLicence2023,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
        )
        val credential = runProcess(issuer, client)
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        credential.credential.shouldNotBeNull()

        val issuerSigned = IssuerSigned.deserialize(credential.credential!!.decodeToByteArray(Base64()))
        issuerSigned.shouldNotBeNull().also { println(it) }
    }

    test("process with ISO atomic attributes") {
        val client = WalletService(
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
        )
        val credential = runProcess(issuer, client)
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        credential.credential.shouldNotBeNull()

        val issuerSigned = IssuerSigned.deserialize(credential.credential!!.decodeToByteArray(Base64()))
        issuerSigned.shouldNotBeNull().also { println(it) }
    }

})

private suspend fun runProcess(
    issuer: IssuerService,
    client: WalletService
): CredentialResponseParameters {
    val metadata = issuer.metadata
    val authnRequest = client.createAuthRequest()
    val codeUrl = issuer.authorize(authnRequest)
    codeUrl.shouldNotBeNull()
    val code = Url(codeUrl).parameters[GRANT_TYPE_CODE]
    code.shouldNotBeNull()
    val tokenRequest = client.createTokenRequestParameters(code)
    val token = issuer.token(tokenRequest)
    val credentialRequest = client.createCredentialRequest(token, metadata)
    return issuer.credential(OpenIdConstants.TOKEN_PREFIX_BEARER + token.accessToken, credentialRequest)
}
