package at.asitplus.wallet.lib.procedures.iso

import at.asitplus.iso.AlternativeDataElementsSet
import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DeviceRequestInfo
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.DocRequest
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.Document
import at.asitplus.iso.ElementReference
import at.asitplus.iso.IsoConstants
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.iso.UseCase
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.procedures.dcql.AuthorityKeyIdentifier
import at.asitplus.wallet.lib.validation.CheckOutcome
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random

val DeviceRequestAdapterTest by matrixSuite {
    val namespace = AtomicAttribute2023.isoNamespace

    fun element(name: String) = ElementReference(namespace, name)

    fun docRequest(
        vararg elements: String,
        docType: String = AtomicAttribute2023.isoDocType,
        requestInfo: DocRequestInfo? = null,
    ) = DocRequest(
        ByteStringWrapper(
            ItemsRequest(
                docType = docType,
                namespaces = mapOf(namespace to ItemsRequestList(elements.map { SingleItemsRequest(it, false) })),
                requestInfo = requestInfo,
            )
        )
    )

    /** A request for [docRequests], with [useCases] in version 1.1, or without in version 1.0. */
    fun deviceRequest(vararg docRequests: DocRequest, useCases: List<UseCase>? = null) = DeviceRequest(
        parsedVersion = if (useCases == null) IsoConstants.VERSION_1_0 else IsoConstants.VERSION_1_1,
        docRequests = arrayOf(*docRequests),
        deviceRequestInfo = useCases?.let { ByteStringWrapper(DeviceRequestInfo(useCases = it)) },
    )

    fun useCase(mandatory: Boolean, vararg documentSets: List<Int>) =
        UseCase(mandatory = mandatory, documentSets = documentSets.map { set -> set.map { it.toUInt() } })

    /** An mdoc of [AtomicAttribute2023], issued with all its data elements, signed with [issuerKey]. */
    suspend fun issued(issuerKey: KeyMaterial = EphemeralKeyWithoutCert()): IssuerSigned = IssuerAgent(
        keyMaterial = issuerKey,
        identifier = "https://issuer.example.com/".toUri(),
        randomSource = RandomSource.Default,
    ).issueCredential(
        DummyCredentialDataProvider.getCredential(
            subjectPublicKey = EphemeralKeyWithoutCert().publicKey,
            credentialScheme = AtomicAttribute2023,
            representation = ISO_MDOC,
        ).getOrThrow()
    ).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.Iso>().issuerSigned

    /** A document of [issuerSigned] that returns only the data elements [elements], issuer-signed. */
    fun document(
        issuerSigned: IssuerSigned,
        vararg elements: String,
        docType: String = AtomicAttribute2023.isoDocType,
    ) = Document(
        docType = docType,
        issuerSigned = IssuerSigned.fromIssuerSignedItems(
            namespacedItems = mapOf(
                namespace to issuerSigned.namespaces.orEmpty().getValue(namespace).entries
                    .map { it.value }.filter { it.elementIdentifier in elements }
            ),
            issuerAuth = issuerSigned.issuerAuth,
        ),
        deviceSigned = DeviceSigned(
            namespaces = ByteStringWrapper(DeviceNameSpaces(mapOf())),
            deviceAuth = DeviceAuth(),
        ),
    )

    "document requests" - {
        "a document returning every requested data element answers the request" {
            val issuerSigned = issued()
            val request = deviceRequest(docRequest(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME))
            val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME))

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome shouldBe CheckOutcome.Passed
        }

        "a document withholding a requested data element does not answer the request" {
            val issuerSigned = issued()
            val request = deviceRequest(docRequest(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME))
            val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME))

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
        }

        "a document of another docType does not answer the request" {
            val issuerSigned = issued()
            val request = deviceRequest(docRequest(CLAIM_GIVEN_NAME))
            val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME, docType = "org.example.other"))

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
        }

        "two requests of one docType need two documents" {
            val issuerSigned = issued()
            val request = deviceRequest(docRequest(CLAIM_GIVEN_NAME), docRequest(CLAIM_GIVEN_NAME))
            val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME))

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
        }

        "documents are assigned to requests regardless of their order" {
            val issuerSigned = issued()
            val request = deviceRequest(docRequest(CLAIM_GIVEN_NAME), docRequest(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME))
            val documents = listOf(
                document(issuerSigned, CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME),
                document(issuerSigned, CLAIM_GIVEN_NAME),
            )

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome shouldBe CheckOutcome.Passed
        }

        "documents of other requests do not answer a request of another docType" {
            val issuerSigned = issued()
            val request = deviceRequest(
                docRequest(CLAIM_GIVEN_NAME),
                docRequest(CLAIM_GIVEN_NAME, docType = "org.example.other"),
            )
            val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME), document(issuerSigned, CLAIM_GIVEN_NAME))

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
        }
    }

    "alternative data elements" - {
        val alternatives = DocRequestInfo(
            alternativeDataElements = listOf(
                AlternativeDataElementsSet(
                    element(CLAIM_GIVEN_NAME),
                    listOf(listOf(element(CLAIM_FAMILY_NAME), element(CLAIM_DATE_OF_BIRTH)))
                )
            )
        )

        "a document returning an alternative element set instead of the requested data element answers the request" {
            val issuerSigned = issued()
            val request = deviceRequest(docRequest(CLAIM_GIVEN_NAME, requestInfo = alternatives))
            val documents = listOf(document(issuerSigned, CLAIM_FAMILY_NAME, CLAIM_DATE_OF_BIRTH))

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome shouldBe CheckOutcome.Passed
        }

        "a document returning only a part of an alternative element set does not answer the request" {
            val issuerSigned = issued()
            val request = deviceRequest(docRequest(CLAIM_GIVEN_NAME, requestInfo = alternatives))
            val documents = listOf(document(issuerSigned, CLAIM_FAMILY_NAME))

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
        }
    }

    "issuer identifiers" - {
        val authorityKeyIdentifier = Random.nextBytes(20)
        val issuerKey = EphemeralKeyWithSelfSignedCert(
            extensions = listOf(
                X509CertificateExtension(
                    oid = AuthorityKeyIdentifier.oid,
                    value = Asn1EncapsulatingOctetString(
                        listOf(AuthorityKeyIdentifier(authorityKeyIdentifier).encodeToTlv())
                    ),
                )
            )
        )
        val request = deviceRequest(
            docRequest(
                CLAIM_GIVEN_NAME,
                requestInfo = DocRequestInfo(issuerIdentifiers = listOf(authorityKeyIdentifier)),
            )
        )

        "a document of an mdoc issued under a requested authority answers the request" {
            val documents = listOf(document(issued(issuerKey), CLAIM_GIVEN_NAME))

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome shouldBe CheckOutcome.Passed
        }

        "a document of an mdoc issued under another authority does not answer the request" {
            val documents = listOf(document(issued(EphemeralKeyWithSelfSignedCert()), CLAIM_GIVEN_NAME))

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
        }
    }

    "use cases" - {
        "a document set of each mandatory use case satisfies the request, in any option" {
            val issuerSigned = issued()
            val request = deviceRequest(
                docRequest(CLAIM_GIVEN_NAME),
                docRequest(CLAIM_DATE_OF_BIRTH, docType = "org.example.other"),
                useCases = listOf(useCase(mandatory = true, listOf(1), listOf(0))),
            )
            val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME))

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome shouldBe CheckOutcome.Passed
        }

        "an optional use case alone does not satisfy a request with a mandatory one" {
            val issuerSigned = issued()
            val request = deviceRequest(
                docRequest(CLAIM_GIVEN_NAME, docType = "org.example.other"),
                docRequest(CLAIM_GIVEN_NAME),
                useCases = listOf(useCase(mandatory = true, listOf(0)), useCase(mandatory = false, listOf(1))),
            )
            val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME))

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
        }

        "one of optional use cases satisfies a request without a mandatory one" {
            val issuerSigned = issued()
            val request = deviceRequest(
                docRequest(CLAIM_GIVEN_NAME, docType = "org.example.other"),
                docRequest(CLAIM_GIVEN_NAME),
                useCases = listOf(useCase(mandatory = false, listOf(0)), useCase(mandatory = false, listOf(1))),
            )
            val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME))

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome shouldBe CheckOutcome.Passed
        }

        "documents beyond a choice of exactly one document set per use case are ignored" {
            val issuerSigned = issued()
            val request = deviceRequest(
                docRequest(CLAIM_GIVEN_NAME),
                docRequest(CLAIM_DATE_OF_BIRTH),
                useCases = listOf(
                    useCase(mandatory = true, listOf(0), listOf(1)),
                    useCase(mandatory = true, listOf(1)),
                ),
            )
            val documents = listOf(
                document(issuerSigned, CLAIM_GIVEN_NAME, CLAIM_DATE_OF_BIRTH),
                document(issuerSigned, CLAIM_DATE_OF_BIRTH),
            )

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome shouldBe CheckOutcome.Passed
        }

        "use cases satisfiable only by several document sets of one of them are not satisfied" {
            val issuerSigned = issued()
            val request = deviceRequest(
                docRequest(CLAIM_GIVEN_NAME),
                docRequest(CLAIM_DATE_OF_BIRTH),
                useCases = listOf(
                    useCase(mandatory = true, listOf(0), listOf(1)),
                    useCase(mandatory = true, listOf(0, 1)),
                ),
            )
            val documents = listOf(
                document(issuerSigned, CLAIM_GIVEN_NAME),
                document(issuerSigned, CLAIM_DATE_OF_BIRTH),
            )

            val outcome = DeviceRequestAdapter(request).checkAcceptedDocuments(documents)

            outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
        }
    }
}
