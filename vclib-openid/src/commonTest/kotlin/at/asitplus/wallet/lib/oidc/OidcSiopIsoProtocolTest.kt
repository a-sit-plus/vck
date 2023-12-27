package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
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
            credentialScheme = ConstantIndex.MobileDrivingLicence2023,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
        )
        val document = runProcess(verifierSiop, walletUrl, holderSiop)

        document.validItems.shouldNotBeEmpty()
        document.invalidItems.shouldBeEmpty()
    }

    "test with Fragment for custom attributes" {
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
        )
        val document = runProcess(verifierSiop, walletUrl, holderSiop)

        document.validItems.shouldNotBeEmpty()
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL" {
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
            credentialScheme = ConstantIndex.MobileDrivingLicence2023,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
            requestedAttributes = listOf(requestedClaim),
        )
        val document = runProcess(verifierSiop, walletUrl, holderSiop)

        document.validItems.shouldNotBeEmpty()
        document.validItems.shouldBeSingleton()
        document.validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
        document.invalidItems.shouldBeEmpty()
    }

})

private suspend fun runProcess(
    verifierSiop: OidcSiopVerifier,
    walletUrl: String,
    holderSiop: OidcSiopWallet
): IsoDocumentParsed {
    val authnRequest = verifierSiop.createAuthnRequestUrl(walletUrl).also { println(it) }

    val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
    authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>().also { println(it) }

    val result = verifierSiop.validateAuthnResponse(authnResponse.url)
    result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessIso>()
    return result.document.also { println(it) }
}
