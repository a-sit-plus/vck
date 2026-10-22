package at.asitplus.wallet.lib.data

import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import io.kotest.assertions.throwables.shouldThrow
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

    "wildcard pointers round-trip as SingleClaimReference" {
        val wire = """{"type":"at.asitplus.wallet.lib.data.JsonClaimReference","normalizedJsonPath":["degrees",null,"type"]}"""
        val reference = joseCompliantSerializer.decodeFromString(SingleClaimReference.serializer(), wire)

        joseCompliantSerializer.encodeToString(SingleClaimReference.serializer(), reference) shouldBe wire
    }

    "concrete-path callers can use the compatibility constructor and getter" {
        val concrete = NormalizedJsonPath(
            NormalizedJsonPathSegment.NameSegment("address"), NormalizedJsonPathSegment.IndexSegment(0u),
        )
        val reference = JsonClaimReference(normalizedJsonPath = concrete)
        reference.path shouldBe DCQLClaimsPathPointer(
            DCQLClaimsPathPointerSegment.NameSegment("address"), DCQLClaimsPathPointerSegment.IndexSegment(0u),
        )
        @Suppress("DEPRECATION")
        reference.normalizedJsonPath shouldBe concrete
    }

    "a wildcard cannot be read as a concrete path" {
        val reference = JsonClaimReference(DCQLClaimsPathPointer("degrees") + null)
        shouldThrow<IllegalStateException> {
            @Suppress("DEPRECATION")
            reference.normalizedJsonPath
        }
    }

    "MdocClaimReference round-trips as SingleClaimReference" {
        val reference: SingleClaimReference = MdocClaimReference(namespace = "eu.europa.ec.eudi.pid.1", claimName = "given_name")

        val serialized = joseCompliantSerializer.encodeToString(SingleClaimReference.serializer(), reference)

        joseCompliantSerializer.decodeFromString(SingleClaimReference.serializer(), serialized) shouldBe reference
    }
}
