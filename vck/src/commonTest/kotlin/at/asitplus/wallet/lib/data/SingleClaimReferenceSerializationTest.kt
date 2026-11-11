package at.asitplus.wallet.lib.data

import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.wallet.lib.agent.DeviceRequestCredentialDisclosure
import io.kotest.assertions.throwables.shouldThrowAny
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.builtins.serializer

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

    "concrete-path callers can use the compatibility constructor" {
        val concrete = NormalizedJsonPath(
            NormalizedJsonPathSegment.NameSegment("address"), NormalizedJsonPathSegment.IndexSegment(0u),
        )
        val reference = JsonClaimReference(normalizedJsonPath = concrete)
        reference.path shouldBe DCQLClaimsPathPointer(
            DCQLClaimsPathPointerSegment.NameSegment("address"), DCQLClaimsPathPointerSegment.IndexSegment(0u),
        )
    }

    "MdocClaimReference round-trips as SingleClaimReference" {
        val reference: SingleClaimReference = MdocClaimReference(namespace = "eu.europa.ec.eudi.pid.1", claimName = "given_name")

        val serialized = joseCompliantSerializer.encodeToString(SingleClaimReference.serializer(), reference)

        joseCompliantSerializer.decodeFromString(SingleClaimReference.serializer(), serialized) shouldBe reference
    }

    "DeviceRequestCredentialDisclosure keeps its data elements as [namespace, claimName] arrays" {
        val serializer = DeviceRequestCredentialDisclosure.serializer(String.serializer())
        val disclosure = DeviceRequestCredentialDisclosure(
            docRequestIndex = 0,
            credential = "credential",
            disclosedAttributes = listOf(
                MdocClaimReference("org.iso.18013.5.1", "family_name"),
                MdocClaimReference("org.iso.18013.5.1", "age_over_18"),
            ),
        )

        val serialized = joseCompliantSerializer.encodeToString(serializer, disclosure)

        // The form of a two-segment NormalizedJsonPath, which disclosedAttributes held before
        serialized shouldBe """{"docRequestIndex":0,"credential":"credential","disclosedAttributes":""" +
                """[["org.iso.18013.5.1","family_name"],["org.iso.18013.5.1","age_over_18"]]}"""
        joseCompliantSerializer.decodeFromString(serializer, serialized) shouldBe disclosure
    }

    "a data element without exactly a name space and an identifier is rejected" - {
        listOf("""["org.iso.18013.5.1"]""", """["org.iso.18013.5.1","family_name","age_over_18"]""").asData() test {
            shouldThrowAny {
                joseCompliantSerializer.decodeFromString(
                    DeviceRequestCredentialDisclosure.serializer(String.serializer()),
                    """{"docRequestIndex":0,"credential":"credential","disclosedAttributes":[$it]}""",
                )
            }
        }
    }
}
