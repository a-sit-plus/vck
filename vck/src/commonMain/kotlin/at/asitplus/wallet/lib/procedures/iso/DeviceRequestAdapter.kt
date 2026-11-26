package at.asitplus.wallet.lib.procedures.iso

import at.asitplus.catchingUnwrapped
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.Document
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.UseCase
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import at.asitplus.wallet.lib.validation.CheckOutcome
import kotlin.jvm.JvmInline

/**
 * Checks the documents of a response against the ISO/IEC 18013-5 [deviceRequest] it answers,
 * as [DCQLQueryAdapter] checks the presentations of a DCQL query.
 */
@JvmInline
value class DeviceRequestAdapter(val deviceRequest: DeviceRequest) {

    /**
     * Whether the accepted [documents] of a response satisfy [deviceRequest]:
     * some document requests satisfy its use cases (a request without use cases requires every document request),
     * as the wallet has to submit them, see [DeviceRetrievalProcedure.requireUseCasesSatisfied], and each of them is
     * answered by its own document, see [DeviceRetrievalProcedure.answers] (ISO/IEC DIS 18013-5:2026, 10.2.4,
     * 10.2.8 step 1).
     *
     * Only accepted documents count: a rejected one counts as if it had not been returned, so the response is only
     * rejected if the request can not be satisfied without it.
     * Further documents, e.g. a second one of a requested docType, are ignored. Documents are assigned regardless of
     * their order, each to one document request at most, so two requests of one docType need two documents. Only
     * issuer-signed data elements count, as only these are attested by the issuer, and error codes instead of data
     * elements (ISO/IEC 18013-5:2021, 8.3.2.1.2.2) do not satisfy a request.
     *
     * The search tries each choice of at most one document set per use case, at most the product of the number of
     * document sets plus one over the use cases, and for each the assignments of documents to its document requests;
     * a `DeviceRequest` has few of both.
     */
    fun checkAcceptedDocuments(documents: List<Document>): CheckOutcome {
        val useCases = DeviceRetrievalProcedure.useCases(deviceRequest)
        val answering = deviceRequest.docRequests.map { docRequest ->
            documents.indices.filter { DeviceRetrievalProcedure.answers(documents[it], docRequest.itemsRequest.value) }
        }
        val satisfied = useCases.choices().any { submitted ->
            catchingUnwrapped { DeviceRetrievalProcedure.requireUseCasesSatisfied(useCases, submitted) }.isSuccess &&
                    assignable(submitted.sorted(), answering, setOf())
        }
        return if (!satisfied)
            CheckOutcome.Failed(
                IllegalArgumentException("No accepted documents satisfy the use cases of ${deviceRequest.describe()}, one document each")
            )
        else
            CheckOutcome.Passed
    }

    /** The document requests of each choice of at most one document set per use case, except the empty choice. */
    private fun List<UseCase>.choices(): Sequence<Set<Int>> =
        fold(sequenceOf(setOf<Int>())) { choices, useCase ->
            choices.flatMap { chosen ->
                sequenceOf(chosen) + useCase.documentSets.asSequence().map { set -> chosen + set.map { it.toInt() } }
            }
        }.filter { it.isNotEmpty() }

    /**
     * Whether each of [docRequests] can be answered by its own document of [answering], the documents that answer
     * each document request, none of [used].
     */
    private fun assignable(docRequests: List<Int>, answering: List<List<Int>>, used: Set<Int>): Boolean =
        docRequests.isEmpty() || answering[docRequests.first()].any { document ->
            document !in used && assignable(docRequests.drop(1), answering, used + document)
        }

    private fun DeviceRequest.describe(): String = docRequests.joinToString { it.itemsRequest.value.describe() }

    private fun ItemsRequest.describe() =
        "$docType ${namespaces.mapValues { (_, requested) -> requested.entries.map { it.dataElementIdentifier } }}"
}
