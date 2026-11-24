package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

val SingleClaimReferenceSerializationTest by matrixSuite {
    "JsonClaimReference round-trips as SingleClaimReference" {
        val reference: SingleClaimReference = JsonClaimReference(DCQLClaimsPathPointer("address") + 0u)

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

    "MdocClaimReference round-trips as SingleClaimReference" {
        val reference: SingleClaimReference = MdocClaimReference(namespace = "eu.europa.ec.eudi.pid.1", claimName = "given_name")

        val serialized = joseCompliantSerializer.encodeToString(SingleClaimReference.serializer(), reference)

        joseCompliantSerializer.decodeFromString(SingleClaimReference.serializer(), serialized) shouldBe reference
    }
}
