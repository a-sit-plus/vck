package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import at.asitplus.wallet.lib.openid.AuthnResponseResult.SuccessIso
import at.asitplus.wallet.lib.openid.AuthnResponseResult.VerifiableDCQLPresentationValidationResults
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier.CreationOptions.Query
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.FAMILY_NAME
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.GIVEN_NAME
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

val OpenId4VpIsoProtocolTest by testSuite {

    withFixtureGenerator(suspend {
        val material = EphemeralKeyWithoutCert()
        val agent = HolderAgent(material).also {
            val issuerAgent = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            it.storeCredential(
                issuerAgent.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        material.publicKey,
                        MobileDrivingLicenceScheme,
                        ISO_MDOC,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
            it.storeCredential(
                issuerAgent.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        material.publicKey,
                        AtomicAttribute2023,
                        ISO_MDOC,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
        }

        object {
            val holderKeyMaterial = material
            val verifierKeyMaterial = EphemeralKeyWithoutCert()
            //println("this is the key:\n" + (verifierKeyMaterial as EphemeralKeyWithoutCert).key.exportPrivateKey().getOrThrow().encodeToDer().encodeToString(Base64Strict))

            val clientId = "https://example.com/rp/${uuid4()}"
            val walletUrl = "https://example.com/wallet/${uuid4()}"
            val holderAgent = agent
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
    }) - {
        "test with Fragment for mDL" {
            val requestOptions = OpenId4VpRequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(GIVEN_NAME))
                )
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions, Query(it.walletUrl))
                .getOrThrow().url
            val authnResponse = it.holderOid4vp
                .createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<SuccessIso>()
                .documents.first().apply {
                    validItems.shouldNotBeEmpty()
                    invalidItems.shouldBeEmpty()
                }
        }

        "test with Fragment for custom attributes" {
            val requestOptions = OpenId4VpRequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC, setOf(CLAIM_GIVEN_NAME))
                )
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions, Query(it.walletUrl))
                .getOrThrow().url
            val authnResponse = it.holderOid4vp
                .createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<SuccessIso>()
                .documents.first().apply {
                    validItems.shouldNotBeEmpty()
                    invalidItems.shouldBeEmpty()
                }
        }

        "Selective Disclosure with mDL" {
            val requestedClaim = FAMILY_NAME
            val requestOptions = OpenId4VpRequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(requestedClaim))
                )
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions, Query(it.walletUrl))
                .getOrThrow().url
            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<SuccessIso>()
                .documents.first().apply {
                    validItems.shouldBeSingleton()
                    validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
                    invalidItems.shouldBeEmpty()
                }
        }

        "Selective Disclosure with mDL (ISO/IEC 18013-7:2024 Annex B)" {
            val requestedClaim = FAMILY_NAME
            val requestOptions = OpenId4VpRequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(requestedClaim))
                ),
                responseMode = OpenIdConstants.ResponseMode.DirectPost,
                responseUrl = "https://example.com/response",
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions, Query(it.walletUrl))
                .getOrThrow().url
            //println("this is the request:\n$authnRequest")

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            val input = authnResponse.params.formUrlEncode()
            //println("this is the response:\n$input")

            it.verifierOid4vp.validateAuthnResponse(input)
                .shouldBeInstanceOf<SuccessIso>()
                .documents.first().apply {
                    validItems.shouldBeSingleton()
                    validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
                    invalidItems.shouldBeEmpty()
                }
        }

        "Selective Disclosure with mDL and encryption (ISO/IEC 18013-7:2024 Annex B)" {
            val requestedClaim = FAMILY_NAME
            val requestOptions = OpenId4VpRequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(requestedClaim))
                ),
                responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                responseUrl = "https://example.com/response",
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions, Query(it.walletUrl)
            ).getOrThrow().url
            //println("this is the request:\n$authnRequest")

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            val input = authnResponse.params.formUrlEncode()
            //println("this is the response:\n$input")

            it.verifierOid4vp.validateAuthnResponse(input)
                .shouldBeInstanceOf<SuccessIso>()
                .documents.first().apply {
                    validItems.shouldBeSingleton()
                    validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
                    invalidItems.shouldBeEmpty()
                }
        }

        "Selective Disclosure with two documents in presentation exchange" {
            val mdlFamilyName = FAMILY_NAME
            val atomicGivenName = CLAIM_GIVEN_NAME
            val requestOptions = OpenId4VpRequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(mdlFamilyName)),
                    RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC, setOf(atomicGivenName))
                ),
                responseMode = OpenIdConstants.ResponseMode.DirectPost,
                responseUrl = "https://example.com/response",
                presentationMechanism = PresentationMechanismEnum.PresentationExchange
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions, Query(it.walletUrl))
                .getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>().apply {
                    // make sure there are two device responses for two credentials returned in the presentation
                    params["vp_token"].shouldNotBeEmpty().shouldNotBeNull().apply {
                        joseCompliantSerializer.decodeFromString<JsonArray>(this).apply {
                            shouldHaveSize(2)
                        }
                    }
                }

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
                .shouldBeInstanceOf<AuthnResponseResult.VerifiablePresentationValidationResults>()
                .validationResults.flatMap { it.shouldBeInstanceOf<SuccessIso>().documents }.apply {
                    first { it.mso.docType == AtomicAttribute2023.isoDocType }
                        .validItems.shouldHaveSingleElement { it.elementIdentifier == atomicGivenName }
                    first { it.mso.docType == MobileDrivingLicenceScheme.isoDocType }
                        .validItems.shouldHaveSingleElement { it.elementIdentifier == mdlFamilyName }
                }
        }

        "Selective Disclosure with two documents in DCQL" {
            val mdlFamilyName = FAMILY_NAME
            val atomicGivenName = CLAIM_GIVEN_NAME
            val requestOptions = OpenId4VpRequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(mdlFamilyName)),
                    RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC, setOf(atomicGivenName))
                ),
                responseMode = OpenIdConstants.ResponseMode.DirectPost,
                responseUrl = "https://example.com/response",
                presentationMechanism = PresentationMechanismEnum.DCQL,
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions, Query(it.walletUrl))
                .getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>().apply {
                    // make sure there are two device responses for two credentials returned in the presentation
                    params["vp_token"].shouldNotBeEmpty().shouldNotBeNull().apply {
                        joseCompliantSerializer.decodeFromString<JsonObject>(this).apply {
                            shouldHaveSize(2)
                        }
                    }
                }

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
                .shouldBeInstanceOf<VerifiableDCQLPresentationValidationResults>()
                .validationResults.shouldHaveSize(2).apply {
                    values.first { it.hasDocType(AtomicAttribute2023.isoDocType) }
                        .shouldBeInstanceOf<SuccessIso>().documents.first()
                        .validItems.shouldHaveSingleElement { it.elementIdentifier == atomicGivenName }
                    values.first { it.hasDocType(MobileDrivingLicenceScheme.isoDocType) }
                        .shouldBeInstanceOf<SuccessIso>().documents.first()
                        .validItems.shouldHaveSingleElement { it.elementIdentifier == mdlFamilyName }
                }
        }

        "Selective Disclosure with mDL JSON Path syntax" {
            val requestOptions = OpenId4VpRequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC, setOf(FAMILY_NAME))
                )
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions, Query(it.walletUrl))
                .getOrThrow().url
            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<SuccessIso>()
                .documents.first().apply {
                    validItems.shouldBeSingleton()
                    validItems.shouldHaveSingleElement { it.elementIdentifier == FAMILY_NAME }
                    invalidItems.shouldBeEmpty()
                }
        }
    }
}

private fun AuthnResponseResult.hasDocType(docType: String): Boolean =
    this.shouldBeInstanceOf<SuccessIso>().documents
        .shouldBeSingleton().first().mso.docType == docType

