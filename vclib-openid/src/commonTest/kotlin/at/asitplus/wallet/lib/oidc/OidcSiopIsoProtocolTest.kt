package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

class OidcSiopIsoProtocolTest : FreeSpec({

    lateinit var relyingPartyUrl: String
    lateinit var walletUrl: String

    lateinit var holderCryptoService: CryptoService
    lateinit var verifierCryptoService: CryptoService

    lateinit var holderAgent: Holder
    lateinit var verifierAgent: Verifier

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderCryptoService = DefaultCryptoService()
        verifierCryptoService = DefaultCryptoService()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent.newDefaultInstance(holderCryptoService)
        verifierAgent = VerifierAgent.newDefaultInstance(verifierCryptoService.publicKey.didEncoded)
        runBlocking {
            val issuerAgent = IssuerAgent.newDefaultInstance(
                DefaultCryptoService(),
                dataProvider = DummyCredentialDataProvider(),
            )
            holderAgent.storeCredentials(
                issuerAgent.issueCredential(
                    subjectPublicKey = holderCryptoService.publicKey,
                    attributeTypes = listOf(ConstantIndex.MobileDrivingLicence2023.vcType),
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC
                ).toStoreCredentialInput()
            )
            holderAgent.storeCredentials(
                issuerAgent.issueCredential(
                    subjectPublicKey = holderCryptoService.publicKey,
                    attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC
                ).toStoreCredentialInput()
            )
        }

        holderSiop = OidcSiopWallet.newInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService
        )
    }

    "test with Fragment for mDL" {
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            ConstantIndex.CredentialRepresentation.ISO_MDOC,
            ConstantIndex.MobileDrivingLicence2023,
            holderSiop
        )

        document.validItems.shouldNotBeEmpty()
        document.invalidItems.shouldBeEmpty()
    }

    "test with Fragment for custom attributes" {
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            ConstantIndex.CredentialRepresentation.ISO_MDOC,
            ConstantIndex.AtomicAttribute2023,
            holderSiop
        )

        document.validItems.shouldNotBeEmpty()
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL" {
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            ConstantIndex.CredentialRepresentation.ISO_MDOC,
            ConstantIndex.MobileDrivingLicence2023,
            holderSiop,
            listOf(requestedClaim)
        )

        document.validItems.shouldNotBeEmpty()
        document.validItems.shouldBeSingleton()
        document.validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
        document.invalidItems.shouldBeEmpty()
    }

})

private suspend fun runProcess(
    verifierSiop: OidcSiopVerifier,
    walletUrl: String,
    credentialRepresentation: ConstantIndex.CredentialRepresentation,
    credentialScheme: ConstantIndex.CredentialScheme,
    holderSiop: OidcSiopWallet,
    requestedAttributes: List<String>? = null,
): IsoDocumentParsed {
    val authnRequest = verifierSiop.createAuthnRequestUrl(
        walletUrl = walletUrl,
        representation = credentialRepresentation,
        credentialScheme = credentialScheme,
        requestedAttributes = requestedAttributes,
    ).also { println(it) }

    val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
    authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>().also { println(it) }

    val result = verifierSiop.validateAuthnResponse(authnResponse.url)
    result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessIso>()
    return result.document.also { println(it) }
}
