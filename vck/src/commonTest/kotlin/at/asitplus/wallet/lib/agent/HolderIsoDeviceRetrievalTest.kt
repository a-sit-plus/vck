package at.asitplus.wallet.lib.agent

import at.asitplus.iso.AlternativeDataElementsSet
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.ElementReference
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.cbor.authorityKeyIdentifiers
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.procedures.dcql.AuthorityKeyIdentifier
import io.github.z4kn4fein.semver.Version
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlin.random.Random

val HolderIsoDeviceRetrievalTest by matrixSuite {

    fixture { runBlocking { createIsoMdocFixture(IsoRevocationMode.STATUS_LIST) } } - {
        "device retrieval: creates one device response with the requested claim" {
            val request = it.verifier.createPresentationRequest(
                calcIsoSessionTranscript = qrSessionTranscript,
            )
            val result = it.holder.createDefaultPresentation(
                request = request,
                credentialPresentationRequest = CredentialPresentationRequest.IsoDeviceRetrieval(
                    isoDeviceRequest(CLAIM_GIVEN_NAME)
                )
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()

            result.deviceResponse.documents.shouldNotBeNull().shouldBeSingleton().single()
                .issuerSigned.namespaces.shouldNotBeNull()
                .getValue(ConstantIndex.AtomicAttribute2023.isoNamespace).entries.shouldBeSingleton()
                .single().value.elementIdentifier shouldBe CLAIM_GIVEN_NAME
            it.verifyPresentation(
                PresentedIsoResponse(request, CreatePresentationResult.DeviceResponse(result.deviceResponse))
            ).assertPresentedClaims(expectDateOfBirth = false)
        }

        "device retrieval: rejects a request for a missing data element" {
            it.holder.createDefaultPresentation(
                request = it.verifier.createPresentationRequest(
                    calcIsoSessionTranscript = qrSessionTranscript,
                ),
                credentialPresentationRequest = CredentialPresentationRequest.IsoDeviceRetrieval(
                    isoDeviceRequest("not_in_the_credential")
                ),
            ).isFailure shouldBe true
        }

        "device retrieval: preserves repeated document requests" {
            val request = CredentialPresentationRequest.IsoDeviceRetrieval(
                DeviceRequest(
                    parsedVersion = Version(1, 0),
                    docRequests = arrayOf(
                        isoDocRequest(CLAIM_GIVEN_NAME),
                        isoDocRequest(CLAIM_DATE_OF_BIRTH),
                    ),
                )
            )

            it.holder.createDefaultPresentation(
                request = it.verifier.createPresentationRequest(
                    calcIsoSessionTranscript = qrSessionTranscript,
                ),
                credentialPresentationRequest = request,
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()
                .deviceResponse.documents.shouldNotBeNull().shouldHaveSize(2)
        }

        "device retrieval: discloses the first alternative of a missing data element the credential has" {
            val alternatives = listOf(listOf(element("also_missing")), listOf(element(CLAIM_DATE_OF_BIRTH)))
            val request = isoRequestWith(
                "not_in_the_credential",
                requestInfo = DocRequestInfo(
                    alternativeDataElements = listOf(
                        AlternativeDataElementsSet(element("not_in_the_credential"), alternatives)
                    )
                ),
            )

            val disclosures = it.holder.disclosuresFor(request)

            disclosures.shouldBeSingleton().single().disclosedAttributes shouldBe
                    listOf(claim(CLAIM_DATE_OF_BIRTH))
        }

        "device retrieval: prefers a requested data element over its alternatives" {
            val request = isoRequestWith(
                CLAIM_GIVEN_NAME,
                requestInfo = DocRequestInfo(
                    alternativeDataElements = listOf(
                        AlternativeDataElementsSet(
                            element(CLAIM_GIVEN_NAME),
                            listOf(listOf(element(CLAIM_DATE_OF_BIRTH)))
                        )
                    )
                ),
            )

            val disclosures = it.holder.disclosuresFor(request)

            disclosures.shouldBeSingleton().single().disclosedAttributes shouldBe
                    listOf(claim(CLAIM_GIVEN_NAME))
        }

        "device retrieval: discloses a data element replacing several requested ones once" {
            val request = isoRequestWith(
                "missing_a", "missing_b",
                requestInfo = DocRequestInfo(
                    alternativeDataElements = listOf("missing_a", "missing_b").map {
                        AlternativeDataElementsSet(element(it), listOf(listOf(element(CLAIM_DATE_OF_BIRTH))))
                    }
                ),
            )

            val disclosures = it.holder.disclosuresFor(request)

            disclosures.shouldBeSingleton().single().disclosedAttributes shouldBe
                    listOf(claim(CLAIM_DATE_OF_BIRTH))
        }

        "device retrieval: matches no credential lacking a data element and all its alternatives" {
            val request = isoRequestWith(
                "not_in_the_credential",
                requestInfo = DocRequestInfo(
                    alternativeDataElements = listOf(
                        AlternativeDataElementsSet(
                            element("not_in_the_credential"),
                            listOf(listOf(element(CLAIM_DATE_OF_BIRTH), element("also_missing")))
                        )
                    )
                ),
            )

            val disclosures = it.holder.disclosuresFor(request)

            disclosures.shouldBeEmpty()
        }

        "device retrieval: matches only credentials of the requested issuer identifiers" {
            val authorityKeyIdentifier = Random.nextBytes(20)
            val otherIssuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(
                    extensions = listOf(
                        X509CertificateExtension(
                            oid = AuthorityKeyIdentifier.oid,
                            value = Asn1EncapsulatingOctetString(
                                listOf(AuthorityKeyIdentifier(authorityKeyIdentifier).encodeToTlv())
                            ),
                        )
                    )
                ),
                identifier = "https://other-issuer.example.com/".toUri(),
                randomSource = RandomSource.Default,
            )
            it.holder.storeCredential(
                otherIssuer.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        subjectPublicKey = it.holderKeyMaterial.publicKey,
                        credentialScheme = ConstantIndex.AtomicAttribute2023,
                        representation = ISO_MDOC,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()
            val request = isoRequestWith(
                CLAIM_GIVEN_NAME,
                requestInfo = DocRequestInfo(issuerIdentifiers = listOf(authorityKeyIdentifier)),
            )

            val disclosures = it.holder.disclosuresFor(request)

            disclosures.shouldBeSingleton().single().credential
                .shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.Iso>()
                .issuerSigned.issuerAuth.authorityKeyIdentifiers().shouldBeSingleton().single() shouldBe
                    authorityKeyIdentifier
        }

        "device retrieval: matching keeps all credentials with the same docType" {
            it.holder.storeCredential(
                it.issuer.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        subjectPublicKey = it.holderKeyMaterial.publicKey,
                        credentialScheme = ConstantIndex.AtomicAttribute2023,
                        representation = ISO_MDOC,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()

            it.holder.matchPresentationRequestAgainstCredentialStore(
                CredentialPresentationRequest.IsoDeviceRetrieval(isoDeviceRequest(CLAIM_GIVEN_NAME))
            ).getOrThrow().shouldBeInstanceOf<IsoDeviceRetrievalMatchingResult<*>>()
                .matchingResult.documentMatches.shouldBeSingleton().single().shouldHaveSize(2)
        }
    }
}

private fun element(name: String) = ElementReference(ConstantIndex.AtomicAttribute2023.isoNamespace, name)

private fun claim(name: String) = MdocClaimReference(ConstantIndex.AtomicAttribute2023.isoNamespace, name)

/** A request for one mdoc of [claimNames] with [requestInfo]. */
private fun isoRequestWith(vararg claimNames: String, requestInfo: DocRequestInfo) =
    CredentialPresentationRequest.IsoDeviceRetrieval(
        DeviceRequest(
            parsedVersion = Version(1, 0),
            docRequests = arrayOf(
                DocRequest(
                    ByteStringWrapper(
                        ItemsRequest(
                            docType = ConstantIndex.AtomicAttribute2023.isoDocType,
                            namespaces = mapOf(
                                ConstantIndex.AtomicAttribute2023.isoNamespace to ItemsRequestList(
                                    claimNames.map { SingleItemsRequest(it, false) }
                                )
                            ),
                            requestInfo = requestInfo,
                        )
                    )
                )
            ),
        )
    )

/** The stored credentials matching the single document request of [request], with their disclosures. */
private suspend fun HolderAgent.disclosuresFor(request: CredentialPresentationRequest.IsoDeviceRetrieval) =
    matchPresentationRequestAgainstCredentialStore(request).getOrThrow()
        .shouldBeInstanceOf<IsoDeviceRetrievalMatchingResult<SubjectCredentialStore.StoreEntry>>()
        .matchingResult.documentMatches.shouldBeSingleton().single()

private fun isoDeviceRequest(vararg claimNames: String) = DeviceRequest(
    parsedVersion = Version(1, 0),
    docRequests = arrayOf(isoDocRequest(*claimNames)),
)

private fun isoDocRequest(vararg claimNames: String) = DocRequest(
    ByteStringWrapper(
        ItemsRequest(
            docType = ConstantIndex.AtomicAttribute2023.isoDocType,
            namespaces = mapOf(
                ConstantIndex.AtomicAttribute2023.isoNamespace to ItemsRequestList(
                    claimNames.map { SingleItemsRequest(it, false) }
                )
            ),
        )
    )
)
