package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.OpenIdConstants
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf

@Suppress("unused")
class OidcSiopIsoProtocolTest : FreeSpec({

    lateinit var relyingPartyUrl: String
    lateinit var walletUrl: String

    lateinit var holderKeyPair: KeyMaterial
    lateinit var verifierKeyPair: KeyMaterial

    lateinit var holderAgent: Holder
    lateinit var verifierAgent: Verifier

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderKeyPair = EphemeralKeyWithSelfSignedCert()
        verifierKeyPair = EphemeralKeyWithSelfSignedCert()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyPair)
        verifierAgent = VerifierAgent(verifierKeyPair)

        val issuerAgent = IssuerAgent(
            EphemeralKeyWithSelfSignedCert(),
            DummyCredentialDataProvider(),
        )
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                holderKeyPair.publicKey,
                MobileDrivingLicenceScheme,
                ConstantIndex.CredentialRepresentation.ISO_MDOC,
            ).getOrThrow().toStoreCredentialInput()
        )
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.ISO_MDOC,
            ).getOrThrow().toStoreCredentialInput()
        )


        holderSiop = OidcSiopWallet(
            holder = holderAgent,
        )
    }

    "test with Fragment for mDL" {
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyPair,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            OidcSiopVerifier.RequestOptions(
                representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                credentialScheme = MobileDrivingLicenceScheme,
                requestedAttributes = listOf(
                    MobileDrivingLicenceDataElements.GIVEN_NAME
                ),
            ),
            holderSiop
        )

        document.validItems.shouldNotBeEmpty()
        document.invalidItems.shouldBeEmpty()
    }

    "test with Fragment for custom attributes" {
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyPair,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            OidcSiopVerifier.RequestOptions(
                representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                requestedAttributes = listOf("given_name"),
            ),
            holderSiop
        )

        document.validItems.shouldNotBeEmpty()
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL" {
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyPair,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            OidcSiopVerifier.RequestOptions(
                representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                credentialScheme = MobileDrivingLicenceScheme,
                requestedAttributes = listOf(requestedClaim),
            ),
            holderSiop,
        )

        document.validItems.shouldNotBeEmpty()
        document.validItems.shouldBeSingleton()
        document.validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL and encryption" {
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyPair,
            relyingPartyUrl = relyingPartyUrl,
            responseUrl = relyingPartyUrl + "/${uuid4()}"
        )
        val requestOptions = OidcSiopVerifier.RequestOptions(
            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
            credentialScheme = MobileDrivingLicenceScheme,
            requestedAttributes = listOf(requestedClaim),
            responseMode = OpenIdConstants.ResponseMode.DIRECT_POST_JWT,
            encryption = true
        )
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = requestOptions
        ).also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        val result = verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessIso>()

        val document = result.document

        document.validItems.shouldNotBeEmpty()
        document.validItems.shouldBeSingleton()
        document.validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL JSON Path syntax" {
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyPair,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            OidcSiopVerifier.RequestOptions(
                representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                credentialScheme = MobileDrivingLicenceScheme,
                requestedAttributes = listOf(MobileDrivingLicenceDataElements.FAMILY_NAME)
            ),
            holderSiop,
        )

        document.validItems.shouldNotBeEmpty()
        document.validItems.shouldBeSingleton()
        document.validItems.shouldHaveSingleElement { it.elementIdentifier == MobileDrivingLicenceDataElements.FAMILY_NAME }
        document.invalidItems.shouldBeEmpty()
    }

})

private suspend fun runProcess(
    verifierSiop: OidcSiopVerifier,
    walletUrl: String,
    requestOptions: OidcSiopVerifier.RequestOptions,
    holderSiop: OidcSiopWallet,
): IsoDocumentParsed {
    val authnRequest = verifierSiop.createAuthnRequestUrl(
        walletUrl = walletUrl,
        requestOptions = requestOptions
    ).also { println(it) }

    val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
    authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>().also { println(it) }

    val result = verifierSiop.validateAuthnResponse(authnResponse.url)
    result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessIso>()
    return result.document.also { println(it) }
}
