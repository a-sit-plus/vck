package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.GIVEN_NAME
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.aroundEach
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf

val OpenId4VpIsoProtocolTest by testSuite {

    lateinit var clientId: String
    lateinit var walletUrl: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier

    testConfig = TestConfig.aroundEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        //println("this is the key:\n" + (verifierKeyMaterial as EphemeralKeyWithoutCert).key.exportPrivateKey().getOrThrow().encodeToDer().encodeToString(Base64Strict))

        clientId = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        val issuerAgent = IssuerAgent(
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    MobileDrivingLicenceScheme,
                    ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    AtomicAttribute2023,
                    ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            decryptionKeyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
            //nonceService = FixedNonceService(),
        )
        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            keyMaterial = holderKeyMaterial,
            randomSource = RandomSource.Default,
        )
        it()
    }

    "test with Fragment for mDL" {
        runProcess(
            verifierOid4vp,
            walletUrl,
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(GIVEN_NAME))
                )
            ),
            holderOid4vp
        ).apply {
            validItems.shouldNotBeEmpty()
            invalidItems.shouldBeEmpty()
        }
    }

    "test with Fragment for custom attributes" {
        runProcess(
            verifierOid4vp,
            walletUrl,
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC, setOf(CLAIM_GIVEN_NAME))
                )
            ),
            holderOid4vp
        ).apply {
            validItems.shouldNotBeEmpty()
            invalidItems.shouldBeEmpty()
        }
    }

    "Selective Disclosure with mDL" {
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        runProcess(
            verifierOid4vp,
            walletUrl,
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(requestedClaim))
                )
            ),
            holderOid4vp,
        ).apply {
            validItems.shouldBeSingleton()
            validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
            invalidItems.shouldBeEmpty()
        }
    }

    "Selective Disclosure with mDL (ISO/IEC 18013-7:2024 Annex B)" {
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        val requestOptions = RequestOptions(
            credentials = setOf(
                RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(requestedClaim))
            ),
            responseMode = OpenIdConstants.ResponseMode.DirectPost,
            responseUrl = "https://example.com/response",
        )
        val authnRequest = verifierOid4vp.createAuthnRequest(
            requestOptions, OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url
        //println("this is the request:\n$authnRequest")

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        val input = authnResponse.params.formUrlEncode()
        //println("this is the response:\n$input")

        verifierOid4vp.validateAuthnResponse(input)
            .shouldBeInstanceOf<AuthnResponseResult.SuccessIso>()
            .documents.first().apply {
                validItems.shouldBeSingleton()
                validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
                invalidItems.shouldBeEmpty()
            }
    }

    "Selective Disclosure with mDL and encryption (ISO/IEC 18013-7:2024 Annex B)" {
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        val requestOptions = RequestOptions(
            credentials = setOf(
                RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(requestedClaim))
            ),
            responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
            responseUrl = "https://example.com/response",
            encryption = true
        )
        val authnRequest = verifierOid4vp.createAuthnRequest(
            requestOptions, OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url
        //println("this is the request:\n$authnRequest")

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        val input = authnResponse.params.formUrlEncode()
        //println("this is the response:\n$input")

        verifierOid4vp.validateAuthnResponse(input)
            .shouldBeInstanceOf<AuthnResponseResult.SuccessIso>()
            .documents.first().apply {
                validItems.shouldBeSingleton()
                validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
                invalidItems.shouldBeEmpty()
            }
    }

    "Selective Disclosure with two documents and encryption (ISO/IEC 18013-7:2024 Annex B)" {
        val mdlFamilyName = MobileDrivingLicenceDataElements.FAMILY_NAME
        val atomicGivenName = CLAIM_GIVEN_NAME
        val requestOptions = RequestOptions(
            credentials = setOf(
                RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(mdlFamilyName)),
                RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC, setOf(atomicGivenName))
            ),
            responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
            responseUrl = "https://example.com/response",
            encryption = true
        )
        val authnRequest = verifierOid4vp.createAuthnRequest(
            requestOptions, OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
            .shouldBeInstanceOf<AuthnResponseResult.VerifiablePresentationValidationResults>()
            .validationResults.flatMap { it.shouldBeInstanceOf<AuthnResponseResult.SuccessIso>().documents }.apply {
                first { it.mso.docType == AtomicAttribute2023.isoDocType }
                    .validItems.shouldHaveSingleElement { it.elementIdentifier == atomicGivenName }
                first { it.mso.docType == MobileDrivingLicenceScheme.isoDocType }
                    .validItems.shouldHaveSingleElement { it.elementIdentifier == mdlFamilyName }
            }
    }

    "Selective Disclosure with mDL JSON Path syntax" {
        runProcess(
            verifierOid4vp,
            walletUrl,
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(
                        MobileDrivingLicenceScheme,
                        ISO_MDOC,
                        setOf(MobileDrivingLicenceDataElements.FAMILY_NAME)
                    )
                )
            ),
            holderOid4vp,
        ).apply {
            validItems.shouldBeSingleton()
            validItems.shouldHaveSingleElement { it.elementIdentifier == MobileDrivingLicenceDataElements.FAMILY_NAME }
            invalidItems.shouldBeEmpty()
        }
    }
}

private suspend fun runProcess(
    verifierOid4vp: OpenId4VpVerifier,
    walletUrl: String,
    requestOptions: RequestOptions,
    holderOid4vp: OpenId4VpHolder,
): IsoDocumentParsed {
    val authnRequest = verifierOid4vp.createAuthnRequest(
        requestOptions, OpenId4VpVerifier.CreationOptions.Query(walletUrl)
    ).getOrThrow().url

    val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
        .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

    return verifierOid4vp.validateAuthnResponse(authnResponse.url)
        .shouldBeInstanceOf<AuthnResponseResult.SuccessIso>()
        .documents.first()
}
