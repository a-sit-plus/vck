package at.asitplus.wallet.lib.openid

import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueIsoMdoc
import at.asitplus.wallet.lib.validation.CheckOutcome
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val IsoSubmissionRequirementsTest by matrixSuite {
    val namespace = AtomicAttribute2023.isoNamespace

    fun request(vararg elements: String, docType: String = AtomicAttribute2023.isoDocType) = ItemsRequest(
        docType = docType,
        namespaces = mapOf(namespace to ItemsRequestList(elements.map { SingleItemsRequest(it, false) })),
    )

    /** An mdoc of [AtomicAttribute2023], issued with all its data elements. */
    suspend fun issued(): IssuerSigned = issueIsoMdoc(
        IssuerAgent(identifier = "https://issuer.example.com/".toUri(), randomSource = RandomSource.Default),
        EphemeralKeyWithoutCert(),
    ).shouldBeInstanceOf<Issuer.IssuedCredential.Iso>().issuerSigned

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

    "a document returning every requested data element answers the request" {
        val issuerSigned = issued()
        val requests = listOf(request(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME))
        val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME))

        val outcome = requests.submissionRequirements(documents)

        outcome shouldBe CheckOutcome.Passed
    }

    "a document withholding a requested data element does not answer the request" {
        val issuerSigned = issued()
        val requests = listOf(request(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME))
        val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME))

        val outcome = requests.submissionRequirements(documents)

        outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
    }

    "a document of another docType does not answer the request" {
        val issuerSigned = issued()
        val requests = listOf(request(CLAIM_GIVEN_NAME))
        val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME, docType = "org.example.other"))

        val outcome = requests.submissionRequirements(documents)

        outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
    }

    "two requests of one docType need two documents" {
        val issuerSigned = issued()
        val requests = listOf(request(CLAIM_GIVEN_NAME), request(CLAIM_GIVEN_NAME))
        val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME))

        val outcome = requests.submissionRequirements(documents)

        outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
    }

    "documents are assigned to requests regardless of their order" {
        val issuerSigned = issued()
        val requests = listOf(request(CLAIM_GIVEN_NAME), request(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME))
        val documents = listOf(
            document(issuerSigned, CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME),
            document(issuerSigned, CLAIM_GIVEN_NAME),
        )

        val outcome = requests.submissionRequirements(documents)

        outcome shouldBe CheckOutcome.Passed
    }

    "documents of other requests do not answer a request of another docType" {
        val issuerSigned = issued()
        val requests = listOf(request(CLAIM_GIVEN_NAME), request(CLAIM_GIVEN_NAME, docType = "org.example.other"))
        val documents = listOf(document(issuerSigned, CLAIM_GIVEN_NAME), document(issuerSigned, CLAIM_GIVEN_NAME))

        val outcome = requests.submissionRequirements(documents)

        outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
    }
}
