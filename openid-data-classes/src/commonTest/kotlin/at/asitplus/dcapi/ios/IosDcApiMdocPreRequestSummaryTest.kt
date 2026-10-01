package at.asitplus.dcapi.ios

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.EncryptionInfo
import at.asitplus.iso.EncryptionParameters
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.signum.indispensable.cosef.CoseEllipticCurve
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.CoseKeyParams
import at.asitplus.signum.indispensable.cosef.CoseKeyType
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.testballoon.matrix.matrixSuite
import io.github.z4kn4fein.semver.Version
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.shouldBe

val IosDcApiMdocPreRequestSummaryTest by matrixSuite {
    test("exact match is consistent") {
        val rawRequest = rawRequest(
            "org.iso.18013.5.1.mDL" to mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to false,
                    "given_name" to false
                )
            )
        )

        val summary = IosDcApiMdocPreRequestSummary(
            documentRequests = listOf(
                IosDcApiMdocPreRequestDocumentRequest(
                    docType = "org.iso.18013.5.1.mDL",
                    namespaces = mapOf(
                        "org.iso.18013.5.1" to mapOf(
                            "family_name" to false,
                            "given_name" to false
                        )
                    )
                )
            )
        )

        summary.isConsistentWith(rawRequest) shouldBe true
    }

    test("ordering differences are still consistent") {
        val rawRequest = rawRequest(
            "org.iso.18013.5.1.mDL" to mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to false,
                    "given_name" to false
                )
            ),
            "eu.europa.ec.eudi.pid.1" to mapOf(
                "eu.europa.ec.eudi.pid.1" to mapOf(
                    "birth_date" to true
                )
            )
        )

        val summary = IosDcApiMdocPreRequestSummary(
            documentRequests = listOf(
                IosDcApiMdocPreRequestDocumentRequest(
                    docType = "eu.europa.ec.eudi.pid.1",
                    namespaces = mapOf(
                        "eu.europa.ec.eudi.pid.1" to mapOf("birth_date" to true)
                    )
                ),
                IosDcApiMdocPreRequestDocumentRequest(
                    docType = "org.iso.18013.5.1.mDL",
                    namespaces = mapOf(
                        "org.iso.18013.5.1" to mapOf(
                            "given_name" to false,
                            "family_name" to false
                        )
                    )
                )
            )
        )

        summary.isConsistentWith(rawRequest) shouldBe true
    }

    test("changed request is inconsistent") {
        val rawRequest = rawRequest(
            "org.iso.18013.5.1.mDL" to mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to false,
                    "given_name" to false
                )
            )
        )

        val summary = IosDcApiMdocPreRequestSummary(
            documentRequests = listOf(
                IosDcApiMdocPreRequestDocumentRequest(
                    docType = "org.iso.18013.5.1.mDL",
                    namespaces = mapOf(
                        "org.iso.18013.5.1" to mapOf(
                            "family_name" to false,
                            "portrait" to false
                        )
                    )
                )
            )
        )

        summary.isConsistentWith(rawRequest) shouldBe false
    }

    test("summary converts to device request") {
        val summary = IosDcApiMdocPreRequestSummary(
            documentRequests = listOf(
                IosDcApiMdocPreRequestDocumentRequest(
                    docType = "org.iso.18013.5.1.mDL",
                    namespaces = mapOf(
                        "org.iso.18013.5.1" to mapOf(
                            "family_name" to false,
                            "given_name" to true
                        )
                    )
                )
            )
        )

        summary.toDeviceRequest().apply {
            parsedVersion shouldBe Version(1, 0)
            version shouldBe "1.0"
            docRequests.shouldBeSingleton().single()
                .itemsRequest.value.apply {
                    docType shouldBe "org.iso.18013.5.1.mDL"
                    namespaces["org.iso.18013.5.1"]!!.entries shouldBe listOf(
                        SingleItemsRequest("family_name", false),
                        SingleItemsRequest("given_name", true),
                    )
                }
        }
    }

    test("changed retain flag is inconsistent") {
        val rawRequest = rawRequest(
            "org.iso.18013.5.1.mDL" to mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "family_name" to false,
                    "given_name" to true
                )
            )
        )

        val summary = IosDcApiMdocPreRequestSummary(
            documentRequests = listOf(
                IosDcApiMdocPreRequestDocumentRequest(
                    docType = "org.iso.18013.5.1.mDL",
                    namespaces = mapOf(
                        "org.iso.18013.5.1" to mapOf(
                            "family_name" to false,
                            "given_name" to false
                        )
                    )
                )
            )
        )

        summary.isConsistentWith(rawRequest) shouldBe false
    }

    test("missing document is inconsistent") {
        val rawRequest = rawRequest(
            "org.iso.18013.5.1.mDL" to mapOf(
                "org.iso.18013.5.1" to mapOf("family_name" to false)
            ),
            "eu.europa.ec.eudi.pid.1" to mapOf(
                "eu.europa.ec.eudi.pid.1" to mapOf("birth_date" to true)
            )
        )

        val summary = IosDcApiMdocPreRequestSummary(
            documentRequests = listOf(
                IosDcApiMdocPreRequestDocumentRequest(
                    docType = "org.iso.18013.5.1.mDL",
                    namespaces = mapOf(
                        "org.iso.18013.5.1" to mapOf("family_name" to false)
                    )
                )
            )
        )

        summary.isConsistentWith(rawRequest) shouldBe false
    }

    test("extra document is inconsistent") {
        val rawRequest = rawRequest(
            "org.iso.18013.5.1.mDL" to mapOf(
                "org.iso.18013.5.1" to mapOf("family_name" to false)
            )
        )

        val summary = IosDcApiMdocPreRequestSummary(
            documentRequests = listOf(
                IosDcApiMdocPreRequestDocumentRequest(
                    docType = "org.iso.18013.5.1.mDL",
                    namespaces = mapOf(
                        "org.iso.18013.5.1" to mapOf("family_name" to false)
                    )
                ),
                IosDcApiMdocPreRequestDocumentRequest(
                    docType = "eu.europa.ec.eudi.pid.1",
                    namespaces = mapOf(
                        "eu.europa.ec.eudi.pid.1" to mapOf("birth_date" to true)
                    )
                )
            )
        )

        summary.isConsistentWith(rawRequest) shouldBe false
    }
}

private fun rawRequest(vararg docs: Pair<String, Map<String, Map<String, Boolean>>>) = IsoMdocRequest(
    deviceRequest = DeviceRequest(
        parsedVersion = Version(1, 0),
        docRequests = docs.map { (docType, namespaces) ->
            DocRequest(
                itemsRequest = ByteStringWrapper(
                    ItemsRequest(
                        docType = docType,
                        namespaces = namespaces.mapValues { (_, elements) ->
                            ItemsRequestList(
                                elements.entries.map { (element, intentToRetain) ->
                                    SingleItemsRequest(element, intentToRetain)
                                }
                            )
                        }
                    )
                )
            )
        }.toTypedArray()
    ),
    encryptionInfo = EncryptionInfo(
        type = DCAPIHandover.TYPE_DCAPI,
        encryptionParameters = EncryptionParameters(
            recipientPublicKey = CoseKey(
                type = CoseKeyType.EC2,
                keyParams = CoseKeyParams.EcYBoolParams(curve = CoseEllipticCurve.P256)
            )
        )
    )
)
