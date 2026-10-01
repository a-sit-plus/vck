package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult.SuccessIso
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.openid.formUrlEncode
import at.asitplus.wallet.lib.openid.CreationOptions.Query
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreIsoMdoc
import at.asitplus.wallet.mdl.MDL_DOCTYPE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.FAMILY_NAME
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.GIVEN_NAME
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

val OpenId4VpIsoProtocolTest by matrixSuite {

    fixture {
        runBlocking {
            val mdlScheme = AttributeIndex.resolveIdentifier(MDL_DOCTYPE, ISO_MDOC)
            val material = EphemeralKeyWithoutCert()
            val agent = HolderAgent(material).also {
                issueAndStoreIsoMdoc(it, material, mdlScheme)
                issueAndStoreIsoMdoc(it, material, AtomicAttribute2023)
            }

            object {
                val mdlScheme = mdlScheme
                val holderKeyMaterial = material
                val verifierKeyMaterial = EphemeralKeyWithoutCert()
                //println("this is the key:\n" + (verifierKeyMaterial as EphemeralKeyWithoutCert).key.exportPrivateKey().getOrThrow().encodeToDer().encodeToString(Base64Strict))

                val clientId = "https://example.com/rp/${uuid4()}"
                val walletUrl = "https://example.com/wallet/${uuid4()}"
                val holderAgent = agent
                val verifierOid4vp = OpenId4VpVerifier(
                    keyMaterial = verifierKeyMaterial,
                    clientIdScheme = ClientIdScheme.RedirectUri(clientId),
                    //nonceService = FixedNonceService(),
                )
                val holderOid4vp = OpenId4VpHolder(
                    holder = holderAgent,
                    keyMaterial = holderKeyMaterial,
                    randomSource = RandomSource.Default,
                )
            }
        }
    } - {
        "test with Fragment for mDL" {
            val requestOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(
                        credentialScheme = it.mdlScheme,
                        representation = ISO_MDOC,
                        attributePaths = setOf(DCQLClaimsPathPointer(GIVEN_NAME))
                    )
                ).toDCQLRequest(),
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions, Query(it.walletUrl))
                .getOrThrow().url
            val authnResponse = it.holderOid4vp
                .createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>().apply {
                    credentialQueryResponseValidations.values
                        .shouldBeSingleton().first().shouldBeSingleton().first().getOrThrow()
                        .shouldBeInstanceOf<SuccessIso>()
                        .documents.first().apply {
                            validItems.shouldNotBeEmpty()
                        }
                }
        }

        "test with Fragment for custom attributes" {
            val requestOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(
                        credentialScheme = AtomicAttribute2023,
                        representation = ISO_MDOC,
                        attributePaths = setOf(DCQLClaimsPathPointer(GIVEN_NAME))
                    )
                ).toDCQLRequest(),
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions, Query(it.walletUrl))
                .getOrThrow().url
            val authnResponse = it.holderOid4vp
                .createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>().apply {
                    credentialQueryResponseValidations.values
                        .shouldBeSingleton().first().shouldBeSingleton().first().getOrThrow()
                        .shouldBeInstanceOf<SuccessIso>()
                        .documents.first().apply {
                            validItems.shouldNotBeEmpty()
                        }
                }
        }

        "Selective Disclosure with mDL" {
            val requestedClaim = FAMILY_NAME
            val requestOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(
                        credentialScheme = it.mdlScheme,
                        representation = ISO_MDOC,
                        attributePaths = setOf(DCQLClaimsPathPointer(requestedClaim))
                    )
                ).toDCQLRequest(),
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions, Query(it.walletUrl))
                .getOrThrow().url
            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>().apply {
                    credentialQueryResponseValidations.values
                        .shouldBeSingleton().first().shouldBeSingleton().first().getOrThrow()
                        .shouldBeInstanceOf<SuccessIso>()
                        .documents.first().apply {
                            validItems.shouldBeSingleton()
                            validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
                        }
                }
        }

        "Selective Disclosure with mDL (ISO/IEC 18013-7:2024 Annex B)" {
            val requestedClaim = FAMILY_NAME
            val requestOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(
                        credentialScheme = it.mdlScheme,
                        representation = ISO_MDOC,
                        attributePaths = setOf(DCQLClaimsPathPointer(requestedClaim))
                    )
                ).toDCQLRequest(),
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

            it.verifierOid4vp.validateAuthnResponse(input).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>().apply {
                    credentialQueryResponseValidations.values
                        .shouldBeSingleton().first()
                        .shouldBeSingleton().first().getOrThrow()
                        .shouldBeInstanceOf<SuccessIso>()
                        .documents.first().apply {
                            validItems.shouldBeSingleton()
                            validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
                        }
                }
        }

        "Selective Disclosure with mDL and encryption (ISO/IEC 18013-7:2024 Annex B)" {
            val requestedClaim = FAMILY_NAME
            val requestOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(
                        credentialScheme = it.mdlScheme,
                        representation = ISO_MDOC,
                        attributePaths = setOf(DCQLClaimsPathPointer(requestedClaim))
                    )
                ).toDCQLRequest(),
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

            it.verifierOid4vp.validateAuthnResponse(input).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>().apply {
                    credentialQueryResponseValidations.values
                        .shouldBeSingleton().first()
                        .shouldBeSingleton().first().getOrThrow().shouldBeInstanceOf<SuccessIso>()
                        .documents.first().apply {
                            validItems.shouldBeSingleton()
                            validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
                        }
                }
        }

        "Selective Disclosure with two documents in DCQL" { scope ->
            val mdlFamilyName = FAMILY_NAME
            val atomicGivenName = CLAIM_GIVEN_NAME
            val requestOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(
                        credentialScheme = scope.mdlScheme,
                        representation = ISO_MDOC,
                        attributePaths = setOf(DCQLClaimsPathPointer(mdlFamilyName))
                    ),
                    RequestOptionsCredential(
                        credentialScheme = AtomicAttribute2023,
                        representation = ISO_MDOC,
                        attributePaths = setOf(DCQLClaimsPathPointer(atomicGivenName))
                    ),
                ).toDCQLRequest(),
                responseMode = OpenIdConstants.ResponseMode.DirectPost,
                responseUrl = "https://example.com/response",
            )
            val authnRequest = scope.verifierOid4vp.createAuthnRequest(requestOptions, Query(scope.walletUrl))
                .getOrThrow().url

            val authnResponse = scope.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>().apply {
                    // make sure there are two device responses for two credentials returned in the presentation
                    params["vp_token"].shouldNotBeEmpty().shouldNotBeNull().apply {
                        joseCompliantSerializer.decodeFromString<JsonObject>(this).apply {
                            shouldHaveSize(2)
                        }
                    }
                }

            scope.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode()).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.shouldHaveSize(2).apply {
                    values.first { it.first().getOrThrow().hasDocType(AtomicAttribute2023.isoDocType) }.first()
                        .getOrThrow().shouldBeInstanceOf<SuccessIso>().documents.first()
                        .validItems.shouldHaveSingleElement { it.elementIdentifier == atomicGivenName }
                    values.first { it.first().getOrThrow().hasDocType(scope.mdlScheme.isoDocType!!) }.first()
                        .getOrThrow().shouldBeInstanceOf<SuccessIso>().documents.first()
                        .validItems.shouldHaveSingleElement { it.elementIdentifier == mdlFamilyName }
                }
        }

        "Selective Disclosure with mDL JSON Path syntax" {
            val requestOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(
                        credentialScheme = it.mdlScheme,
                        representation = ISO_MDOC,
                        attributePaths = setOf(DCQLClaimsPathPointer(FAMILY_NAME))
                    )
                ).toDCQLRequest(),
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions, Query(it.walletUrl))
                .getOrThrow().url
            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>().apply {
                    credentialQueryResponseValidations.values
                        .shouldBeSingleton().first()
                        .shouldBeSingleton().first().getOrThrow().shouldBeInstanceOf<SuccessIso>()
                        .documents.first().apply {
                            validItems.shouldBeSingleton()
                            validItems.shouldHaveSingleElement { it.elementIdentifier == FAMILY_NAME }
                        }
                }
        }
    }
}

private fun Verifier.VerifyPresentationResult.hasDocType(docType: String): Boolean =
    this.shouldBeInstanceOf<SuccessIso>().documents
        .shouldBeSingleton().first().mso.docType == docType

