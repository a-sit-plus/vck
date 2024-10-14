package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.OpenIdConstants
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
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

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial

    lateinit var holderAgent: Holder

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        val issuerAgent = IssuerAgent(
            EphemeralKeyWithSelfSignedCert(),
            DummyCredentialDataProvider(),
        )
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                DummyCredentialDataProvider().getCredential(
                    holderKeyMaterial.publicKey,
                    MobileDrivingLicenceScheme,
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                DummyCredentialDataProvider().getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )


        holderSiop = OidcSiopWallet(
            holder = holderAgent,
            keyMaterial = holderKeyMaterial
        )
    }

    "test with Fragment for mDL" {
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            OidcSiopVerifier.RequestOptions(
                credentials = setOf(
                    OidcSiopVerifier.RequestOptionsCredential(
                        MobileDrivingLicenceScheme, ConstantIndex.CredentialRepresentation.ISO_MDOC, listOf(
                            MobileDrivingLicenceDataElements.GIVEN_NAME
                        )
                    )
                )
            ),
            holderSiop
        )

        document.validItems.shouldNotBeEmpty()
        document.invalidItems.shouldBeEmpty()
    }

    "test with Fragment for custom attributes" {
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            OidcSiopVerifier.RequestOptions(
                credentials = setOf(
                    OidcSiopVerifier.RequestOptionsCredential(
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        listOf(CLAIM_GIVEN_NAME)
                    )
                )
            ),
            holderSiop
        )

        document.validItems.shouldNotBeEmpty()
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL" {
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            OidcSiopVerifier.RequestOptions(
                credentials = setOf(
                    OidcSiopVerifier.RequestOptionsCredential(
                        MobileDrivingLicenceScheme,
                        ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        listOf(requestedClaim)
                    )
                )
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
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
        val requestOptions = OidcSiopVerifier.RequestOptions(
            credentials = setOf(
                OidcSiopVerifier.RequestOptionsCredential(
                    MobileDrivingLicenceScheme, ConstantIndex.CredentialRepresentation.ISO_MDOC, listOf(requestedClaim)
                )
            ),
            responseMode = OpenIdConstants.ResponseMode.DIRECT_POST_JWT,
            responseUrl = "https://example.com/response",
            encryption = true
        )
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = requestOptions
        )

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        val result = verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessIso>()

        val document = result.documents.first()

        document.validItems.shouldNotBeEmpty()
        document.validItems.shouldBeSingleton()
        document.validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL JSON Path syntax" {
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            OidcSiopVerifier.RequestOptions(
                credentials = setOf(
                    OidcSiopVerifier.RequestOptionsCredential(
                        MobileDrivingLicenceScheme,
                        ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        listOf(MobileDrivingLicenceDataElements.FAMILY_NAME)
                    )
                )
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
    )

    val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
    authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

    val result = verifierSiop.validateAuthnResponse(authnResponse.url)
    result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessIso>()
    return result.documents.first()
}
