package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

private fun docRequest(docType: String) = DocRequest(
    ByteStringWrapper(
        ItemsRequest(
            docType = docType,
            namespaces = mapOf(
                "org.iso.18013.5.1" to ItemsRequestList(listOf(SingleItemsRequest("family_name", false)))
            ),
        )
    )
)

/** Use cases that say more than "every document request is required". */
private data class UseCases(val name: String, val useCases: List<UseCase>)

private val docRequests = listOf(docRequest("org.iso.18013.5.1.mDL"), docRequest("eu.europa.ec.eudi.pid.1"))

val DeviceRequestUseCasesTest by matrixSuite {

    "has no deviceRequestInfo and version 1.0" - {
        test("for mandatory use cases with one document set each, referencing every document request") {
            val useCases = listOf(UseCase(true, listOf(listOf(0u))), UseCase(true, listOf(listOf(1u))))

            val deviceRequest = DeviceRequest.forUseCases(docRequests, useCases)

            deviceRequest.apply {
                parsedVersion shouldBe IsoConstants.VERSION_1_0
                deviceRequestInfo shouldBe null
                this.docRequests.toList() shouldBe docRequests
            }
        }
    }

    "has the use cases as deviceRequestInfo in version 1.1" - {
        listOf(
            UseCases(
                "for an optional use case",
                listOf(UseCase(true, listOf(listOf(0u))), UseCase(false, listOf(listOf(1u)))),
            ),
            UseCases(
                "for a use case with several document sets",
                listOf(UseCase(true, listOf(listOf(0u), listOf(1u)))),
            ),
            UseCases(
                "for purpose hints",
                listOf(
                    UseCase(
                        mandatory = true,
                        documentSets = listOf(listOf(0u, 1u)),
                        purposeHints = mapOf(UseCase.PURPOSE_CONTROLLER_ISO to UseCase.PURPOSE_AGE_VERIFICATION),
                    )
                ),
            ),
        ).asData(nameFn = { it.name }) test { case ->
            val deviceRequest = DeviceRequest.forUseCases(docRequests, case.useCases)

            deviceRequest.apply {
                parsedVersion shouldBe IsoConstants.VERSION_1_1
                deviceRequestInfo.shouldNotBeNull().value.useCases shouldBe case.useCases
            }
        }
    }

    "fails" - {
        test("without use cases") {
            val useCases = listOf<UseCase>()

            shouldThrow<IllegalArgumentException> { DeviceRequest.forUseCases(docRequests, useCases) }
        }

        test("for a document request no use case references") {
            val useCases = listOf(UseCase(true, listOf(listOf(0u))))

            shouldThrow<IllegalArgumentException> { DeviceRequest.forUseCases(docRequests, useCases) }
        }

        test("for a document request that does not exist, also if every document request is required") {
            val useCases = listOf(UseCase(true, listOf(listOf(0u, 1u, 99u))))

            shouldThrow<IllegalArgumentException> { DeviceRequest.forUseCases(docRequests, useCases) }
        }

        test("for a document set contained in another one of its use case") {
            val useCases = listOf(UseCase(true, listOf(listOf(0u, 1u), listOf(1u))))

            shouldThrow<IllegalArgumentException> { DeviceRequest.forUseCases(docRequests, useCases) }
        }

        test("for equal document sets of a use case") {
            val useCases = listOf(UseCase(true, listOf(listOf(0u, 1u), listOf(1u, 0u))))

            shouldThrow<IllegalArgumentException> { DeviceRequest.forUseCases(docRequests, useCases) }
        }
    }
}
