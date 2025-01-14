package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.wallet.lib.agent.*
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

class OpenId4VpIsoProtocolTest : FreeSpec({

    lateinit var clientId: String
    lateinit var walletUrl: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        clientId = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        val issuerAgent = IssuerAgent(EphemeralKeyWithSelfSignedCert())
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    MobileDrivingLicenceScheme,
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )


        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            keyMaterial = holderKeyMaterial
        )
    }

    "test with Fragment for mDL" {
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = OpenId4VpVerifier.ClientIdScheme.RedirectUri(clientId),
        )
        val document = runProcess(
            verifierOid4vp,
            walletUrl,
            OpenId4VpVerifier.RequestOptions(
                credentials = setOf(
                    OpenId4VpVerifier.RequestOptionsCredential(
                        MobileDrivingLicenceScheme, ConstantIndex.CredentialRepresentation.ISO_MDOC, listOf(
                            MobileDrivingLicenceDataElements.GIVEN_NAME
                        )
                    )
                )
            ),
            holderOid4vp
        )

        document.validItems.shouldNotBeEmpty()
        document.invalidItems.shouldBeEmpty()
    }

    "test with Fragment for custom attributes" {
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = OpenId4VpVerifier.ClientIdScheme.RedirectUri(clientId),
        )
        val document = runProcess(
            verifierOid4vp,
            walletUrl,
            OpenId4VpVerifier.RequestOptions(
                credentials = setOf(
                    OpenId4VpVerifier.RequestOptionsCredential(
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        listOf(ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME)
                    )
                )
            ),
            holderOid4vp
        )

        document.validItems.shouldNotBeEmpty()
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL" {
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = OpenId4VpVerifier.ClientIdScheme.RedirectUri(clientId),
        )
        val document = runProcess(
            verifierOid4vp,
            walletUrl,
            OpenId4VpVerifier.RequestOptions(
                credentials = setOf(
                    OpenId4VpVerifier.RequestOptionsCredential(
                        MobileDrivingLicenceScheme,
                        ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        listOf(requestedClaim)
                    )
                )
            ),
            holderOid4vp,
        )

        document.validItems.shouldBeSingleton()
        document.validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL and encryption (ISO/IEC 18013-7:2024 Annex B)" {
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = OpenId4VpVerifier.ClientIdScheme.RedirectUri(clientId),
        )
        val requestOptions = OpenId4VpVerifier.RequestOptions(
            credentials = setOf(
                OpenId4VpVerifier.RequestOptionsCredential(
                    MobileDrivingLicenceScheme, ConstantIndex.CredentialRepresentation.ISO_MDOC, listOf(requestedClaim)
                )
            ),
            responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
            responseUrl = "https://example.com/response",
            encryption = true
        )
        val authnRequest = verifierOid4vp.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = requestOptions
        )

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OpenId4VpVerifier.AuthnResponseResult.SuccessIso>()

        val document = result.documents.first()

        document.validItems.shouldBeSingleton()
        document.validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL JSON Path syntax" {
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = OpenId4VpVerifier.ClientIdScheme.RedirectUri(clientId),
        )
        val document = runProcess(
            verifierOid4vp,
            walletUrl,
            OpenId4VpVerifier.RequestOptions(
                credentials = setOf(
                    OpenId4VpVerifier.RequestOptionsCredential(
                        MobileDrivingLicenceScheme,
                        ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        listOf(MobileDrivingLicenceDataElements.FAMILY_NAME)
                    )
                )
            ),
            holderOid4vp,
        )

        document.validItems.shouldBeSingleton()
        document.validItems.shouldHaveSingleElement { it.elementIdentifier == MobileDrivingLicenceDataElements.FAMILY_NAME }
        document.invalidItems.shouldBeEmpty()
    }

})

private suspend fun runProcess(
    verifierOid4vp: OpenId4VpVerifier,
    walletUrl: String,
    requestOptions: OpenId4VpVerifier.RequestOptions,
    holderOid4vp: OpenId4VpHolder,
): IsoDocumentParsed {
    val authnRequest = verifierOid4vp.createAuthnRequestUrl(
        walletUrl = walletUrl,
        requestOptions = requestOptions
    )

    val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
    authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

    val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
    result.shouldBeInstanceOf<OpenId4VpVerifier.AuthnResponseResult.SuccessIso>()
    return result.documents.first()
}