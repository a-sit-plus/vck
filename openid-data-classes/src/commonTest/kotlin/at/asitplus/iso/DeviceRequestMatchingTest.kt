package at.asitplus.iso

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlin.random.Random

private const val NAMESPACE = "org.iso.18013.5.1"
private const val DOC_TYPE = "org.iso.18013.5.1.mDL"
private const val OTHER_DOC_TYPE = "org.example.other"
private const val GIVEN_NAME = "given_name"
private const val FAMILY_NAME = "family_name"
private const val BIRTH_DATE = "birth_date"
private const val MISSING = "not_in_the_credential"

private fun element(name: String) = ElementReference(NAMESPACE, name)

private fun item(name: String, digestId: UInt) = IssuerSignedItem(
    digestId = digestId,
    random = Random.nextBytes(16),
    elementIdentifier = name,
    elementValue = "value of $name",
)

/** An mdoc of [docType] with the issuer-signed data elements [names] and [authorityKeyIdentifiers]. */
private fun credential(
    vararg names: String,
    docType: String = DOC_TYPE,
    authorityKeyIdentifiers: List<ByteArray> = listOf(),
) = IsoMdocCredential(
    docType = docType,
    issuerSignedItems = names.withIndex().associate { (index, name) -> element(name) to item(name, index.toUInt()) },
    authorityKeyIdentifiers = authorityKeyIdentifiers,
)

/** An mdoc with all data elements of these tests, of [docType]. */
private fun fullCredential(docType: String = DOC_TYPE, authorityKeyIdentifiers: List<ByteArray> = listOf()) =
    credential(GIVEN_NAME, FAMILY_NAME, BIRTH_DATE, docType = docType, authorityKeyIdentifiers = authorityKeyIdentifiers)

private fun itemsRequest(
    vararg names: String,
    docType: String = DOC_TYPE,
    requestInfo: DocRequestInfo? = null,
) = ItemsRequest(
    docType = docType,
    namespaces = mapOf(NAMESPACE to ItemsRequestList(names.map { SingleItemsRequest(it, false) })),
    requestInfo = requestInfo,
)

private fun docRequest(vararg names: String, docType: String = DOC_TYPE, requestInfo: DocRequestInfo? = null) =
    DocRequest(ByteStringWrapper(itemsRequest(*names, docType = docType, requestInfo = requestInfo)))

/** A request for [docRequests], with [useCases] in version 1.1, or without in version 1.0. */
private fun deviceRequest(vararg docRequests: DocRequest, useCases: List<UseCase>? = null) = DeviceRequest(
    parsedVersion = if (useCases == null) IsoConstants.VERSION_1_0 else IsoConstants.VERSION_1_1,
    docRequests = arrayOf(*docRequests),
    deviceRequestInfo = useCases?.let { ByteStringWrapper(DeviceRequestInfo(useCases = it)) },
)

/** A use case of [documentSets], each listing the positions of its document requests. */
private fun useCase(mandatory: Boolean, vararg documentSets: List<Int>) =
    UseCase(mandatory = mandatory, documentSets = documentSets.map { set -> set.map { it.toUInt() } })

private fun ids(vararg indices: Int) = indices.map { DocRequestId(it) }.toSet()

private fun alternatives(requested: String, vararg sets: List<String>) = DocRequestInfo(
    alternativeDataElements = listOf(
        AlternativeDataElementsSet(element(requested), sets.map { set -> set.map { element(it) } })
    )
)

val DeviceRequestMatchingTest by matrixSuite {

    "matching" - {
        test("discloses the requested data elements with their items, in the order of the request") {
            val credential = fullCredential()
            val request = itemsRequest(FAMILY_NAME, GIVEN_NAME)

            val match = request.match(credential)

            match.getOrThrow().disclosedItems shouldBe mapOf(
                element(FAMILY_NAME) to credential.issuerSignedItems.getValue(element(FAMILY_NAME)),
                element(GIVEN_NAME) to credential.issuerSignedItems.getValue(element(GIVEN_NAME)),
            )
        }

        test("fails for a missing data element") {
            val request = itemsRequest(GIVEN_NAME, MISSING)

            val match = request.match(fullCredential())

            match.isFailure shouldBe true
        }

        test("fails for another docType") {
            val request = itemsRequest(GIVEN_NAME)

            val match = request.match(fullCredential(docType = OTHER_DOC_TYPE))

            match.isFailure shouldBe true
        }

        test("keeps one result per credential and document request, failures included") {
            val credentials = listOf(fullCredential(), fullCredential(docType = OTHER_DOC_TYPE), fullCredential())
            val request = deviceRequest(docRequest(GIVEN_NAME), docRequest(BIRTH_DATE, docType = OTHER_DOC_TYPE))

            val result = request.findDocRequestMatches(credentials)

            result.apply {
                docRequestMatchingResults.keys shouldBe ids(0, 1)
                docRequestMatchingResults.getValue(DocRequestId(0)).map { it.isSuccess } shouldBe
                        listOf(true, false, true)
                docRequestMatchingResults.getValue(DocRequestId(1)).map { it.isSuccess } shouldBe
                        listOf(false, true, false)
                docRequestMatches.getValue(DocRequestId(0)).map { it.first } shouldBe listOf(0u, 2u)
                docRequestMatches.getValue(DocRequestId(1)).map { it.first } shouldBe listOf(1u)
            }
        }

        test("keeps repeated document requests apart") {
            val request = deviceRequest(docRequest(GIVEN_NAME), docRequest(BIRTH_DATE))

            val result = request.findDocRequestMatches(listOf(fullCredential()))

            result.docRequestMatches.mapValues { (_, matches) -> matches.single().second.disclosedElements } shouldBe
                    mapOf(DocRequestId(0) to listOf(element(GIVEN_NAME)), DocRequestId(1) to listOf(element(BIRTH_DATE)))
        }
    }

    "alternative data elements" - {
        test("discloses the first alternative of a missing data element the credential has") {
            val request = itemsRequest(MISSING, requestInfo = alternatives(MISSING, listOf("also_missing"), listOf(BIRTH_DATE)))

            val match = request.match(fullCredential())

            match.getOrThrow().disclosedElements shouldBe listOf(element(BIRTH_DATE))
        }

        test("prefers a requested data element over its alternatives") {
            val request = itemsRequest(GIVEN_NAME, requestInfo = alternatives(GIVEN_NAME, listOf(BIRTH_DATE)))

            val match = request.match(fullCredential())

            match.getOrThrow().disclosedElements shouldBe listOf(element(GIVEN_NAME))
        }

        test("discloses an alternative at the position of the requested data element it replaces") {
            val request = itemsRequest(
                GIVEN_NAME, MISSING, FAMILY_NAME,
                requestInfo = alternatives(MISSING, listOf(BIRTH_DATE)),
            )

            val match = request.match(fullCredential())

            match.getOrThrow().disclosedElements shouldBe
                    listOf(element(GIVEN_NAME), element(BIRTH_DATE), element(FAMILY_NAME))
        }

        test("discloses a data element replacing several requested ones once") {
            val request = itemsRequest(
                "missing_a", "missing_b",
                requestInfo = DocRequestInfo(
                    alternativeDataElements = listOf("missing_a", "missing_b").map {
                        AlternativeDataElementsSet(element(it), listOf(listOf(element(BIRTH_DATE))))
                    }
                ),
            )

            val match = request.match(fullCredential())

            match.getOrThrow().disclosedElements shouldBe listOf(element(BIRTH_DATE))
        }

        test("fails for a credential lacking a data element and all its alternatives") {
            val request = itemsRequest(MISSING, requestInfo = alternatives(MISSING, listOf(BIRTH_DATE, "also_missing")))

            val match = request.match(fullCredential())

            match.isFailure shouldBe true
        }
    }

    "issuer identifiers" - {
        val authorityKeyIdentifier = Random.nextBytes(20)
        val request = itemsRequest(
            GIVEN_NAME,
            requestInfo = DocRequestInfo(issuerIdentifiers = listOf(authorityKeyIdentifier)),
        )

        test("a credential issued under a requested authority matches") {
            val credential = fullCredential(
                authorityKeyIdentifiers = listOf(Random.nextBytes(20), authorityKeyIdentifier.copyOf())
            )

            val match = request.match(credential)

            match.isSuccess shouldBe true
        }

        test("a credential issued under another authority does not match") {
            val credential = fullCredential(authorityKeyIdentifiers = listOf(Random.nextBytes(20)))

            val match = request.match(credential)

            match.isFailure shouldBe true
        }

        test("a credential without authority key identifiers does not match") {
            val match = request.match(fullCredential())

            match.isFailure shouldBe true
        }

        test("a credential under another authority does not answer the request") {
            val credential = fullCredential(authorityKeyIdentifiers = listOf(Random.nextBytes(20)))

            val answered = request.isAnsweredBy(credential)

            answered shouldBe false
        }

        test("disclosing a credential under another authority fails") {
            val credential = fullCredential(authorityKeyIdentifiers = listOf(Random.nextBytes(20)))

            val result = request.checkDisclosure(credential, setOf(element(GIVEN_NAME)))

            result.isFailure shouldBe true
        }

        test("disclosing a credential under a requested authority answers the request") {
            val credential = fullCredential(authorityKeyIdentifiers = listOf(authorityKeyIdentifier.copyOf()))

            val result = request.checkDisclosure(credential, setOf(element(GIVEN_NAME)))

            result.isSuccess shouldBe true
        }

        test("only a document under a requested authority satisfies the request") {
            val deviceRequest = deviceRequest(DocRequest(ByteStringWrapper(request)))
            val documents = listOf(
                fullCredential(authorityKeyIdentifiers = listOf(Random.nextBytes(20))),
                fullCredential(authorityKeyIdentifiers = listOf(authorityKeyIdentifier.copyOf())),
            )

            val results = listOf(documents.take(1), documents).map { deviceRequest.checkAcceptedDocuments(it) }

            results.map { it.isSuccess } shouldBe listOf(false, true)
        }
    }

    "use cases" - {
        test("a request without use cases has one mandatory use case of all its document requests") {
            val request = deviceRequest(docRequest(GIVEN_NAME), docRequest(BIRTH_DATE))

            val useCases = request.requestedUseCases

            useCases shouldBe listOf(useCase(mandatory = true, listOf(0, 1)))
        }

        test("a request with use cases has them") {
            val useCases = listOf(useCase(mandatory = true, listOf(0)), useCase(mandatory = false, listOf(1)))
            val request = deviceRequest(docRequest(GIVEN_NAME), docRequest(BIRTH_DATE), useCases = useCases)

            val requested = request.requestedUseCases

            requested shouldBe useCases
        }

        test("the document requests of a document set of each mandatory use case satisfy the request") {
            val request = deviceRequest(
                docRequest(GIVEN_NAME), docRequest(BIRTH_DATE), docRequest(FAMILY_NAME),
                useCases = listOf(useCase(mandatory = true, listOf(0), listOf(1)), useCase(mandatory = false, listOf(2))),
            )

            val result = request.checkUseCaseRequirements(ids(1, 2))

            result.isSuccess shouldBe true
        }

        test("a request without use cases requires every document request") {
            val request = deviceRequest(docRequest(GIVEN_NAME), docRequest(BIRTH_DATE))

            val result = request.checkUseCaseRequirements(ids(0))

            result.isFailure shouldBe true
        }

        test("an optional use case alone does not satisfy a request with a mandatory one") {
            val request = deviceRequest(
                docRequest(GIVEN_NAME), docRequest(BIRTH_DATE),
                useCases = listOf(useCase(mandatory = true, listOf(0)), useCase(mandatory = false, listOf(1))),
            )

            val result = request.checkUseCaseRequirements(ids(1))

            result.isFailure shouldBe true
        }

        test("no document request satisfies no use case, although each is optional") {
            val request = deviceRequest(docRequest(GIVEN_NAME), useCases = listOf(useCase(mandatory = false, listOf(0))))

            val result = request.checkUseCaseRequirements(setOf())

            result.isFailure shouldBe true
        }

        test("satisfying several document sets of a use case fails") {
            val request = deviceRequest(
                docRequest(GIVEN_NAME), docRequest(BIRTH_DATE),
                useCases = listOf(useCase(mandatory = true, listOf(0), listOf(1)), useCase(mandatory = true, listOf(1))),
            )

            val result = request.checkUseCaseRequirements(ids(0, 1))

            result.isFailure shouldBe true
        }

        test("a document request in no satisfied document set of a use case fails") {
            val request = deviceRequest(
                docRequest(GIVEN_NAME), docRequest(BIRTH_DATE),
                useCases = listOf(useCase(mandatory = true, listOf(0)), useCase(mandatory = false, listOf(0, 1))),
            )

            val result = request.checkUseCaseRequirements(ids(1))

            result.isFailure shouldBe true
        }

        test("a document request that is not one of the request fails") {
            val request = deviceRequest(docRequest(GIVEN_NAME))

            val result = request.checkUseCaseRequirements(ids(0, 1))

            result.isFailure shouldBe true
        }

        test("the items request of a document request is the one at its position") {
            val request = deviceRequest(docRequest(GIVEN_NAME), docRequest(BIRTH_DATE))

            val itemsRequest = request.itemsRequest(DocRequestId(1))

            itemsRequest shouldBe itemsRequest(BIRTH_DATE)
        }

        test("there is no items request of a position that is not a document request") {
            val request = deviceRequest(docRequest(GIVEN_NAME))

            val result = runCatching { request.itemsRequest(DocRequestId(1)) }

            result.exceptionOrNull().shouldBeInstanceOf<IllegalArgumentException>()
        }
    }

    "disclosure" - {
        test("disclosing the requested data elements answers the request") {
            val request = itemsRequest(GIVEN_NAME, FAMILY_NAME)

            val result = request.checkDisclosure(fullCredential(), setOf(element(GIVEN_NAME), element(FAMILY_NAME)))

            result.isSuccess shouldBe true
        }

        test("a holder may disclose a later alternative of a requested data element") {
            val request = itemsRequest(
                GIVEN_NAME,
                requestInfo = alternatives(GIVEN_NAME, listOf(FAMILY_NAME), listOf(BIRTH_DATE)),
            )

            val result = request.checkDisclosure(fullCredential(), setOf(element(BIRTH_DATE)))

            result.isSuccess shouldBe true
        }

        test("rejects a data element that is neither requested nor an alternative") {
            val request = itemsRequest(GIVEN_NAME)

            val result = request.checkDisclosure(fullCredential(), setOf(element(GIVEN_NAME), element(FAMILY_NAME)))

            result.isFailure shouldBe true
        }

        test("rejects withholding a requested data element") {
            val request = itemsRequest(GIVEN_NAME, FAMILY_NAME)

            val result = request.checkDisclosure(fullCredential(), setOf(element(GIVEN_NAME)))

            result.isFailure shouldBe true
        }

        test("rejects a requested data element disclosed together with a part of its alternative set") {
            val request = itemsRequest(GIVEN_NAME, requestInfo = alternatives(GIVEN_NAME, listOf(BIRTH_DATE, FAMILY_NAME)))

            val result = request.checkDisclosure(fullCredential(), setOf(element(GIVEN_NAME), element(BIRTH_DATE)))

            result.isFailure shouldBe true
        }

        test("rejects a requested data element disclosed together with its alternative set") {
            val request = itemsRequest(GIVEN_NAME, requestInfo = alternatives(GIVEN_NAME, listOf(BIRTH_DATE)))

            val result = request.checkDisclosure(fullCredential(), setOf(element(GIVEN_NAME), element(BIRTH_DATE)))

            result.isFailure shouldBe true
        }

        test("rejects a data element the credential does not have") {
            val request = itemsRequest(GIVEN_NAME)

            val result = request.checkDisclosure(credential(FAMILY_NAME), setOf(element(GIVEN_NAME)))

            result.isFailure shouldBe true
        }

        test("rejects a credential of another docType") {
            val request = itemsRequest(GIVEN_NAME)

            val result = request.checkDisclosure(fullCredential(docType = OTHER_DOC_TYPE), setOf(element(GIVEN_NAME)))

            result.isFailure shouldBe true
        }
    }

    "accepted documents" - {
        test("a document returning every requested data element answers the request") {
            val request = deviceRequest(docRequest(GIVEN_NAME, FAMILY_NAME))

            val result = request.checkAcceptedDocuments(listOf(credential(GIVEN_NAME, FAMILY_NAME)))

            result.isSuccess shouldBe true
        }

        test("further data elements do not matter") {
            val request = deviceRequest(docRequest(GIVEN_NAME))

            val result = request.checkAcceptedDocuments(listOf(fullCredential()))

            result.isSuccess shouldBe true
        }

        test("a document withholding a requested data element does not answer the request") {
            val request = deviceRequest(docRequest(GIVEN_NAME, FAMILY_NAME))

            val result = request.checkAcceptedDocuments(listOf(credential(GIVEN_NAME)))

            result.isFailure shouldBe true
        }

        test("a document of another docType does not answer the request") {
            val request = deviceRequest(docRequest(GIVEN_NAME))

            val result = request.checkAcceptedDocuments(listOf(credential(GIVEN_NAME, docType = OTHER_DOC_TYPE)))

            result.isFailure shouldBe true
        }

        test("two requests of one docType need two documents") {
            val request = deviceRequest(docRequest(GIVEN_NAME), docRequest(GIVEN_NAME))

            val result = request.checkAcceptedDocuments(listOf(credential(GIVEN_NAME)))

            result.isFailure shouldBe true
        }

        test("documents are assigned to requests regardless of their order") {
            val request = deviceRequest(docRequest(GIVEN_NAME), docRequest(GIVEN_NAME, FAMILY_NAME))
            val documents = listOf(credential(GIVEN_NAME, FAMILY_NAME), credential(GIVEN_NAME))

            val result = request.checkAcceptedDocuments(documents)

            result.isSuccess shouldBe true
        }

        test("documents of other requests do not answer a request of another docType") {
            val request = deviceRequest(docRequest(GIVEN_NAME), docRequest(GIVEN_NAME, docType = OTHER_DOC_TYPE))
            val documents = listOf(credential(GIVEN_NAME), credential(GIVEN_NAME))

            val result = request.checkAcceptedDocuments(documents)

            result.isFailure shouldBe true
        }

        test("a document returning an alternative element set instead of the requested data element answers the request") {
            val request = deviceRequest(
                docRequest(GIVEN_NAME, requestInfo = alternatives(GIVEN_NAME, listOf(FAMILY_NAME, BIRTH_DATE)))
            )

            val result = request.checkAcceptedDocuments(listOf(credential(FAMILY_NAME, BIRTH_DATE)))

            result.isSuccess shouldBe true
        }

        test("a document returning only a part of an alternative element set does not answer the request") {
            val request = deviceRequest(
                docRequest(GIVEN_NAME, requestInfo = alternatives(GIVEN_NAME, listOf(FAMILY_NAME, BIRTH_DATE)))
            )

            val result = request.checkAcceptedDocuments(listOf(credential(FAMILY_NAME)))

            result.isFailure shouldBe true
        }

        test("a document set of each mandatory use case satisfies the request, in any option") {
            val request = deviceRequest(
                docRequest(GIVEN_NAME),
                docRequest(BIRTH_DATE, docType = OTHER_DOC_TYPE),
                useCases = listOf(useCase(mandatory = true, listOf(1), listOf(0))),
            )

            val result = request.checkAcceptedDocuments(listOf(credential(GIVEN_NAME)))

            result.isSuccess shouldBe true
        }

        test("an optional use case alone does not satisfy a request with a mandatory one") {
            val request = deviceRequest(
                docRequest(GIVEN_NAME, docType = OTHER_DOC_TYPE),
                docRequest(GIVEN_NAME),
                useCases = listOf(useCase(mandatory = true, listOf(0)), useCase(mandatory = false, listOf(1))),
            )

            val result = request.checkAcceptedDocuments(listOf(credential(GIVEN_NAME)))

            result.isFailure shouldBe true
        }

        test("one of optional use cases satisfies a request without a mandatory one") {
            val request = deviceRequest(
                docRequest(GIVEN_NAME, docType = OTHER_DOC_TYPE),
                docRequest(GIVEN_NAME),
                useCases = listOf(useCase(mandatory = false, listOf(0)), useCase(mandatory = false, listOf(1))),
            )

            val result = request.checkAcceptedDocuments(listOf(credential(GIVEN_NAME)))

            result.isSuccess shouldBe true
        }

        test("documents beyond a choice of exactly one document set per use case are ignored") {
            val request = deviceRequest(
                docRequest(GIVEN_NAME),
                docRequest(BIRTH_DATE),
                useCases = listOf(useCase(mandatory = true, listOf(0), listOf(1)), useCase(mandatory = true, listOf(1))),
            )
            val documents = listOf(credential(GIVEN_NAME, BIRTH_DATE), credential(BIRTH_DATE))

            val result = request.checkAcceptedDocuments(documents)

            result.isSuccess shouldBe true
        }

        test("use cases satisfiable only by several document sets of one of them are not satisfied") {
            val request = deviceRequest(
                docRequest(GIVEN_NAME),
                docRequest(BIRTH_DATE),
                useCases = listOf(useCase(mandatory = true, listOf(0), listOf(1)), useCase(mandatory = true, listOf(0, 1))),
            )
            val documents = listOf(credential(GIVEN_NAME), credential(BIRTH_DATE))

            val result = request.checkAcceptedDocuments(documents)

            result.isFailure shouldBe true
        }
    }

    "types" - {
        test("a DocRequestId is a position starting from 0") {
            val result = runCatching { DocRequestId(-1) }

            result.exceptionOrNull().shouldBeInstanceOf<IllegalArgumentException>()
        }

        test("an mdoc of IssuerSigned has its issuer-signed items by name space and identifier") {
            val credential = fullCredential()
            val issuerAuth = CoseSigned.create(
                CoseHeader(algorithm = CoseAlgorithm.Signature.RS256),
                null,
                null,
                CryptoSignature.RSA(byteArrayOf()),
                MobileSecurityObject.serializer(),
            )
            val issuerSigned = IssuerSigned.fromIssuerSignedItems(
                namespacedItems = mapOf(NAMESPACE to credential.issuerSignedItems.values.toList()),
                issuerAuth = issuerAuth,
            )

            val result = IsoMdocCredential.of(DOC_TYPE, issuerSigned, credential.authorityKeyIdentifiers)

            result shouldBe credential
        }

        test("a submission option serializes its data elements as arrays in JSON") {
            val option = DocRequestSubmissionOption("credential", listOf(element(GIVEN_NAME)))
            val serializer = DocRequestSubmissionOption.serializer(String.serializer())

            val json = Json.encodeToString(serializer, option)

            json shouldBe """{"credential":"credential","disclosedElements":[["$NAMESPACE","$GIVEN_NAME"]]}"""
        }

        test("a submission option deserializes its data elements from arrays in JSON") {
            val json = """{"credential":"credential","disclosedElements":[["$NAMESPACE","$GIVEN_NAME"]]}"""
            val serializer = DocRequestSubmissionOption.serializer(String.serializer())

            val option = Json.decodeFromString(serializer, json)

            option shouldBe DocRequestSubmissionOption("credential", listOf(element(GIVEN_NAME)))
        }

        test("an ElementReference is not decoded from an array of another size") {
            val json = """["$NAMESPACE","$GIVEN_NAME","extra"]"""

            val result = runCatching { Json.decodeFromString(ElementReference.ArraySerializer, json) }

            result.exceptionOrNull().shouldBeInstanceOf<IllegalArgumentException>()
        }

        test("a DocRequestId is shown as its position") {
            val id = DocRequestId(2)

            val shown = "$id"

            shown shouldBe "2"
        }

        test("an mdoc shows its authority key identifiers in hex") {
            val credential = credential(authorityKeyIdentifiers = listOf(byteArrayOf(0x0a, 0x1b)))

            val shown = credential.toString()

            shown shouldContain "authorityKeyIdentifiers=[0A1B]"
        }
    }
}
