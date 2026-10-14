package at.asitplus.etsi

import at.asitplus.etsi.relyingParty.WrpClaim
import at.asitplus.etsi.relyingParty.WrpClaimPathSegment
import at.asitplus.etsi.relyingParty.WrpClaimValue
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe

val WrpClaimSerializationTest by matrixSuite {

    "a claim path is a claims path pointer of names, null for all elements, and indexes" {
        val json = """{"path":["nationalities",null,0],"values":["AT",1,true]}"""

        val claim = joseCompliantSerializer.decodeFromString(WrpClaim.serializer(), json)

        claim.path shouldBe listOf(
            WrpClaimPathSegment.Name("nationalities"),
            WrpClaimPathSegment.AllElements,
            WrpClaimPathSegment.Index(0U),
        )
        claim.values shouldBe listOf(WrpClaimValue.Text("AT"), WrpClaimValue.Integer(1), WrpClaimValue.Bool(true))
        joseCompliantSerializer.encodeToString(WrpClaim.serializer(), claim) shouldBe json
    }

    "a string that looks like a number is a name" {
        joseCompliantSerializer.decodeFromString(WrpClaim.serializer(), """{"path":["0"]}""").path shouldBe
                listOf(WrpClaimPathSegment.Name("0"))
    }

    "negative indexes, fractions, and objects are no claim path segments" {
        listOf("""{"path":[-1]}""", """{"path":[1.5]}""", """{"path":[{}]}""").forEach {
            shouldThrowAny { joseCompliantSerializer.decodeFromString(WrpClaim.serializer(), it) }
        }
    }
}
