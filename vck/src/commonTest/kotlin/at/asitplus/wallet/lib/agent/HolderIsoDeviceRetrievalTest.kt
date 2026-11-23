package at.asitplus.wallet.lib.agent

import at.asitplus.iso.AlternativeDataElementsSet
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DeviceRequestInfo
import at.asitplus.iso.DocRequest
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.ElementReference
import at.asitplus.iso.IsoConstants
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.iso.UseCase
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.cbor.authorityKeyIdentifiers
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.IsoDeviceRetrieval
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

    fixture { runBlocking { createIsoMdocFixture(IsoRevocationMode.STATUS_LIST, StatusListTokenFormat.CWT) } } - {
        "device retrieval: creates one device response with the requested claim" {
            val request = it.verifier.createPresentationRequest(
                calcIsoSessionTranscript = qrSessionTranscript,
            )
            val result = it.holder.createDefaultPresentation(
                request = request,
                credentialPresentationRequest = IsoDeviceRetrieval(isoDeviceRequest(CLAIM_GIVEN_NAME))
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
                credentialPresentationRequest = IsoDeviceRetrieval(isoDeviceRequest("not_in_the_credential")),
            ).isFailure shouldBe true
        }

        "device retrieval: preserves repeated document requests" {
            val request = IsoDeviceRetrieval(
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
                IsoDeviceRetrieval(isoDeviceRequest(CLAIM_GIVEN_NAME))
            ).getOrThrow().shouldBeInstanceOf<IsoDeviceRetrievalMatchingResult<*>>()
                .matchingResult.documentMatches.shouldBeSingleton().single().shouldHaveSize(2)
        }

        "use cases: a request without use cases has one mandatory use case of all its document requests" {
            val request = IsoDeviceRetrieval(
                DeviceRequest(
                    parsedVersion = Version(1, 0),
                    docRequests = arrayOf(isoDocRequest(CLAIM_GIVEN_NAME), isoDocRequest("not_in_the_credential")),
                )
            )

            val result = it.holder.matchingResultFor(request)

            result.useCases shouldBe listOf(
                HolderUseCase(
                    mandatory = true,
                    documentSets = listOf(HolderDocumentSet(docRequestIndices = listOf(0, 1), satisfiable = false)),
                    purposeHints = mapOf(),
                )
            )
        }

        "use cases: shows each use case with its purpose hints and which document sets are satisfiable" {
            val purposeHints = mapOf(UseCase.PURPOSE_CONTROLLER_ISO to UseCase.PURPOSE_AGE_VERIFICATION)
            val request = isoRequestWithUseCases(
                listOf(isoDocRequest(CLAIM_GIVEN_NAME), isoDocRequest("not_in_the_credential")),
                useCase(mandatory = true, listOf(1), listOf(0), purposeHints = purposeHints),
            )

            val result = it.holder.matchingResultFor(request)

            result.useCases shouldBe listOf(
                HolderUseCase(
                    mandatory = true,
                    documentSets = listOf(
                        HolderDocumentSet(docRequestIndices = listOf(1), satisfiable = false),
                        HolderDocumentSet(docRequestIndices = listOf(0), satisfiable = true),
                    ),
                    purposeHints = purposeHints,
                )
            )
        }

        "use cases: the default submission presents a satisfiable document set of each mandatory use case only" {
            val request = isoRequestWithUseCases(
                listOf(isoDocRequest(CLAIM_GIVEN_NAME), isoDocRequest(CLAIM_DATE_OF_BIRTH)),
                useCase(mandatory = true, listOf(0)),
                useCase(mandatory = false, listOf(1)),
            )
            val result = it.holder.matchingResultFor(request)

            val submission = result.toDefaultSubmission().getOrThrow()

            submission.map { it.docRequestIndex } shouldBe listOf(0)
        }

        "use cases: without a mandatory use case, the default submission presents the first satisfiable one" {
            val request = isoRequestWithUseCases(
                listOf(isoDocRequest("not_in_the_credential"), isoDocRequest(CLAIM_GIVEN_NAME)),
                useCase(mandatory = false, listOf(0)),
                useCase(mandatory = false, listOf(1)),
            )
            val result = it.holder.matchingResultFor(request)

            val submission = result.toDefaultSubmission().getOrThrow()

            submission.map { it.docRequestIndex } shouldBe listOf(1)
        }

        "use cases: a selection presents the chosen optional use case too" {
            val request = isoRequestWithUseCases(
                listOf(isoDocRequest(CLAIM_GIVEN_NAME), isoDocRequest(CLAIM_DATE_OF_BIRTH)),
                useCase(mandatory = true, listOf(0)),
                useCase(mandatory = false, listOf(1)),
            )
            val result = it.holder.matchingResultFor(request)

            val selection = result.useCases.associateWith { it.documentSets.single() }

            val submission = result.toSubmission(selection).getOrThrow()

            submission.map { it.docRequestIndex } shouldBe listOf(0, 1)
        }

        "use cases: a selection rejects" - { fixture ->
            val otherUseCase = HolderUseCase(
                mandatory = false,
                documentSets = listOf(HolderDocumentSet(docRequestIndices = listOf(1), satisfiable = true)),
                purposeHints = mapOf(),
            )
            listOf(
                InvalidSelection("no document set of a mandatory use case") {
                    mapOf(it[1] to it[1].documentSets[0])
                },
                InvalidSelection("a document set that can not be satisfied") {
                    mapOf(it[0] to it[0].documentSets[0])
                },
                InvalidSelection("a document set of another use case") {
                    mapOf(it[0] to it[1].documentSets[0])
                },
                InvalidSelection("a use case not of the request") {
                    mapOf(it[0] to it[0].documentSets[1], otherUseCase to otherUseCase.documentSets[0])
                },
            ).asData(nameFn = { it.name }) test { invalid ->
                val request = isoRequestWithUseCases(
                    listOf(
                        isoDocRequest("not_in_the_credential"),
                        isoDocRequest(CLAIM_GIVEN_NAME),
                        isoDocRequest(CLAIM_DATE_OF_BIRTH),
                    ),
                    useCase(mandatory = true, listOf(0), listOf(1)),
                    useCase(mandatory = false, listOf(2)),
                )
                val result = fixture.holder.matchingResultFor(request)
                val selection = invalid.choose(result.useCases)

                val submission = result.toSubmission(selection)

                submission.isFailure shouldBe true
            }
        }

        "use cases: the default submission avoids satisfying several document sets of a use case" {
            val request = isoRequestWithUseCases(
                listOf(isoDocRequest(CLAIM_GIVEN_NAME), isoDocRequest(CLAIM_DATE_OF_BIRTH)),
                useCase(mandatory = true, listOf(0), listOf(1)),
                useCase(mandatory = true, listOf(1)),
            )
            val result = it.holder.matchingResultFor(request)

            val submission = result.toDefaultSubmission().getOrThrow()

            submission.map { it.docRequestIndex } shouldBe listOf(1)
        }

        "use cases: a selection satisfying several document sets of a use case is rejected" {
            val request = isoRequestWithUseCases(
                listOf(isoDocRequest(CLAIM_GIVEN_NAME), isoDocRequest(CLAIM_DATE_OF_BIRTH)),
                useCase(mandatory = true, listOf(0), listOf(1)),
                useCase(mandatory = true, listOf(1)),
            )
            val result = it.holder.matchingResultFor(request)
            val selection = result.useCases.let { useCases ->
                mapOf(useCases[0] to useCases[0].documentSets[0], useCases[1] to useCases[1].documentSets[0])
            }

            val submission = result.toSubmission(selection)

            submission.isFailure shouldBe true
        }

        "use cases: a selection of no use case is rejected, although each is optional" {
            val request = isoRequestWithUseCases(
                listOf(isoDocRequest(CLAIM_GIVEN_NAME)),
                useCase(mandatory = false, listOf(0)),
            )
            val result = it.holder.matchingResultFor(request)

            val submission = result.toSubmission(mapOf())

            submission.isFailure shouldBe true
        }

        "use cases: presents every matching credential if a unique document set is not required" {
            it.holder.storeCredential(
                it.issuer.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        subjectPublicKey = it.holderKeyMaterial.publicKey,
                        credentialScheme = ConstantIndex.AtomicAttribute2023,
                        representation = ISO_MDOC,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()
            val request = isoRequestWith(
                CLAIM_GIVEN_NAME,
                requestInfo = DocRequestInfo(uniqueDocSetRequired = false),
            )

            val result = it.holder.createDefaultPresentation(
                request = it.verifier.createPresentationRequest(calcIsoSessionTranscript = qrSessionTranscript),
                credentialPresentationRequest = request,
            )

            result.getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()
                .deviceResponse.documents.shouldNotBeNull().shouldHaveSize(2)
        }

        "submission: a wallet may disclose a later alternative of a requested data element" {
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
            val submission = it.disclosure(docRequestIndex = 0, CLAIM_DATE_OF_BIRTH)

            val result = it.present(request, submission)

            result.getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()
                .deviceResponse.documents.shouldNotBeNull().shouldBeSingleton().single()
                .issuerSigned.namespaces.shouldNotBeNull()
                .getValue(ConstantIndex.AtomicAttribute2023.isoNamespace).entries
                .map { it.value.elementIdentifier } shouldBe listOf(CLAIM_DATE_OF_BIRTH)
        }

        "submission: rejects a data element that is neither requested nor an alternative" {
            val request = IsoDeviceRetrieval(isoDeviceRequest(CLAIM_GIVEN_NAME))
            val submission = it.disclosure(docRequestIndex = 0, CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME)

            val result = it.present(request, submission)

            result.isFailure shouldBe true
        }

        "submission: rejects a requested data element disclosed together with a part of its alternative set" {
            val request = isoRequestWith(
                CLAIM_GIVEN_NAME,
                requestInfo = DocRequestInfo(
                    alternativeDataElements = listOf(
                        AlternativeDataElementsSet(
                            element(CLAIM_GIVEN_NAME),
                            listOf(listOf(element(CLAIM_DATE_OF_BIRTH), element(CLAIM_FAMILY_NAME)))
                        )
                    )
                ),
            )
            val submission = it.disclosure(docRequestIndex = 0, CLAIM_GIVEN_NAME, CLAIM_DATE_OF_BIRTH)

            val result = it.present(request, submission)

            result.isFailure shouldBe true
        }

        "submission: rejects a requested data element disclosed together with its alternative set" {
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
            val submission = it.disclosure(docRequestIndex = 0, CLAIM_GIVEN_NAME, CLAIM_DATE_OF_BIRTH)

            val result = it.present(request, submission)

            result.isFailure shouldBe true
        }

        "submission: rejects a document request that is in no document set of a satisfied use case" {
            val request = isoRequestWithUseCases(
                listOf(isoDocRequest(CLAIM_GIVEN_NAME), isoDocRequest(CLAIM_DATE_OF_BIRTH)),
                useCase(mandatory = true, listOf(0)),
            )
            val submissions = arrayOf(
                it.disclosure(docRequestIndex = 0, CLAIM_GIVEN_NAME),
                it.disclosure(docRequestIndex = 1, CLAIM_DATE_OF_BIRTH),
            )

            val result = it.present(request, *submissions)

            result.isFailure shouldBe true
        }
    }
}

private fun element(name: String) = ElementReference(ConstantIndex.AtomicAttribute2023.isoNamespace, name)

private fun claim(name: String) = MdocClaimReference(ConstantIndex.AtomicAttribute2023.isoNamespace, name)

/** A request for one mdoc of [claimNames] with [requestInfo]. */
private fun isoRequestWith(vararg claimNames: String, requestInfo: DocRequestInfo) = IsoDeviceRetrieval(
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

/** A selection a test expects to be rejected, named [name], made by [choose] from the use cases of a result. */
private class InvalidSelection(
    val name: String,
    val choose: (List<HolderUseCase>) -> Map<HolderUseCase, HolderDocumentSet>,
)

/** A request of version 1.1 for [docRequests] with [useCases]. */
private fun isoRequestWithUseCases(docRequests: List<DocRequest>, vararg useCases: UseCase) = IsoDeviceRetrieval(
    DeviceRequest(
        parsedVersion = IsoConstants.VERSION_1_1,
        docRequests = docRequests.toTypedArray(),
        deviceRequestInfo = ByteStringWrapper(DeviceRequestInfo(useCases.toList())),
    )
)

/** A use case of [documentSets], each listing the positions of its document requests. */
private fun useCase(mandatory: Boolean, vararg documentSets: List<Int>, purposeHints: Map<String, Int>? = null) =
    UseCase(
        mandatory = mandatory,
        documentSets = documentSets.map { set -> set.map { it.toUInt() } },
        purposeHints = purposeHints,
    )

private suspend fun HolderAgent.matchingResultFor(request: IsoDeviceRetrieval) =
    matchPresentationRequestAgainstCredentialStore(request).getOrThrow()
        .shouldBeInstanceOf<IsoDeviceRetrievalMatchingResult<SubjectCredentialStore.StoreEntry>>()
        .matchingResult

/** A disclosure of [claimNames] of the single stored mdoc for the document request at [docRequestIndex]. */
private suspend fun IsoMdocFixture.disclosure(docRequestIndex: Int, vararg claimNames: String) =
    DeviceRequestCredentialDisclosure<SubjectCredentialStore.StoreEntry>(
        docRequestIndex = docRequestIndex,
        credential = holderCredentialStore.getCredentials().getOrThrow()
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Iso>().single(),
        disclosedAttributes = claimNames.map { claim(it) },
    )

/** Presents [submissions], which the wallet built itself, for [request]. */
private suspend fun IsoMdocFixture.present(
    request: IsoDeviceRetrieval,
    vararg submissions: DeviceRequestCredentialDisclosure<SubjectCredentialStore.StoreEntry>,
) = holder.createPresentation(
    request = verifier.createPresentationRequest(calcIsoSessionTranscript = qrSessionTranscript),
    credentialPresentation = CredentialPresentation.IsoDeviceRetrievalPresentation(request, submissions.toList()),
)

/** The stored credentials matching the single document request of [request], with their disclosures. */
private suspend fun HolderAgent.disclosuresFor(request: IsoDeviceRetrieval) =
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
