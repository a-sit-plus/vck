package at.asitplus.wallet.lib.data

import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

val SingleClaimReferenceSerializationTest by matrixSuite {
    "JsonClaimReference round-trips as SingleClaimReference" {
        val reference: SingleClaimReference = JsonClaimReference(
            NormalizedJsonPath(
                NormalizedJsonPathSegment.NameSegment("address"),
                NormalizedJsonPathSegment.IndexSegment(0u),
            )
        )

        val serialized = joseCompliantSerializer.encodeToString(SingleClaimReference.serializer(), reference)

        serialized shouldBe
                """{"type":"at.asitplus.wallet.lib.data.JsonClaimReference","normalizedJsonPath":["address",0]}"""
        joseCompliantSerializer.decodeFromString(SingleClaimReference.serializer(), serialized) shouldBe reference
    }

    "MdocClaimReference round-trips as SingleClaimReference" {
        val reference: SingleClaimReference = MdocClaimReference(namespace = "eu.europa.ec.eudi.pid.1", claimName = "given_name")

        val serialized = joseCompliantSerializer.encodeToString(SingleClaimReference.serializer(), reference)

        joseCompliantSerializer.decodeFromString(SingleClaimReference.serializer(), serialized) shouldBe reference
    }
}
