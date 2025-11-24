package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
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
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.engine.runBlocking
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf

val OpenId4VpIsoProtocolTest by testSuite {

    withFixtureGenerator {
        object {
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val verifierKeyMaterial = EphemeralKeyWithoutCert()
            //println("this is the key:\n" + (verifierKeyMaterial as EphemeralKeyWithoutCert).key.exportPrivateKey().getOrThrow().encodeToDer().encodeToString(Base64Strict))

            val clientId = "https://example.com/rp/${uuid4()}"
            val walletUrl = "https://example.com/wallet/${uuid4()}"
            val holderAgent = HolderAgent(holderKeyMaterial).also {
                runBlocking {
                    val issuerAgent = IssuerAgent(
                        keyMaterial = EphemeralKeyWithSelfSignedCert(),
                        identifier = "https://issuer.example.com/".toUri(),
                        randomSource = RandomSource.Default
                    )
                    it.storeCredential(
                        issuerAgent.issueCredential(
                            DummyCredentialDataProvider.getCredential(
                                holderKeyMaterial.publicKey,
                                MobileDrivingLicenceScheme,
                                ISO_MDOC,
                            ).getOrThrow()
                        ).getOrThrow().toStoreCredentialInput()
                    )
                    it.storeCredential(
                        issuerAgent.issueCredential(
                            DummyCredentialDataProvider.getCredential(
                                holderKeyMaterial.publicKey,
                                AtomicAttribute2023,
                                ISO_MDOC,
                            ).getOrThrow()
                        ).getOrThrow().toStoreCredentialInput()
                    )
                }
            }
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                decryptionKeyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.RedirectUri(clientId),
                //nonceService = FixedNonceService(),
            )
            val holderOid4vp = OpenId4VpHolder(
                holder = holderAgent,
                keyMaterial = holderKeyMaterial,
                randomSource = RandomSource.Default,
            )
        }
    } - {
        "test with Fragment for mDL" {
            runProcess(
                it.verifierOid4vp,
                it.walletUrl,
                RequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(GIVEN_NAME))
                    )
                ),
                it.holderOid4vp
            ).apply {
                validItems.shouldNotBeEmpty()
                invalidItems.shouldBeEmpty()
            }
        }

        "test with Fragment for custom attributes" {
            runProcess(
                it.verifierOid4vp,
                it.walletUrl,
                RequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC, setOf(CLAIM_GIVEN_NAME))
                    )
                ),
                it.holderOid4vp
            ).apply {
                validItems.shouldNotBeEmpty()
                invalidItems.shouldBeEmpty()
            }
        }

        "Selective Disclosure with mDL" {
            val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
            runProcess(
                it.verifierOid4vp,
                it.walletUrl,
                RequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(requestedClaim))
                    )
                ),
                it.holderOid4vp,
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
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions, OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url
            //println("this is the request:\n$authnRequest")

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            val input = authnResponse.params.formUrlEncode()
            //println("this is the response:\n$input")

            it.verifierOid4vp.validateAuthnResponse(input)
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
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions, OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url
            //println("this is the request:\n$authnRequest")

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            val input = authnResponse.params.formUrlEncode()
            //println("this is the response:\n$input")

            it.verifierOid4vp.validateAuthnResponse(input)
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
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions, OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
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
                it.verifierOid4vp,
                it.walletUrl,
                RequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(
                            MobileDrivingLicenceScheme,
                            ISO_MDOC,
                            setOf(MobileDrivingLicenceDataElements.FAMILY_NAME)
                        )
                    )
                ),
                it.holderOid4vp,
            ).apply {
                validItems.shouldBeSingleton()
                validItems.shouldHaveSingleElement { it.elementIdentifier == MobileDrivingLicenceDataElements.FAMILY_NAME }
                invalidItems.shouldBeEmpty()
            }
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
