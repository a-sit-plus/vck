package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

val SdJwtTypeMetadataClaimInformationPathTest by matrixSuite {
    test("claim paths serialize as arrays of names, indices, and null") {
        mapOf(
            """["name"]""" to SdJwtTypeMetadataClaimInformationPath("name"),
            """["address","street_address"]""" to SdJwtTypeMetadataClaimInformationPath("address", "street_address"),
            """["degrees",null,"type"]""" to SdJwtTypeMetadataClaimInformationPath("degrees") + null + "type",
            """["nationalities",1]""" to SdJwtTypeMetadataClaimInformationPath("nationalities") + 1uL,
        ).forEach { (wire, path) ->
            Json.encodeToString(path) shouldBe wire
            Json.decodeFromString<SdJwtTypeMetadataClaimInformationPath>(wire) shouldBe path
        }
    }

    test("negative numeric path segments are rejected at parse time") {
        shouldThrow<IllegalArgumentException> {
            Json.decodeFromString<SdJwtTypeMetadataClaimInformationPath>("""["degrees", -1]""")
        }
        shouldThrow<IllegalArgumentException> {
            Json.decodeFromString<SdJwtTypeMetadataClaimInformationPath>("""[-1]""")
        }
    }

    test("path indexes exceeding Int.MAX_VALUE are rejected at parse time") {
        val tooBig = Int.MAX_VALUE.toLong() + 1L
        shouldThrow<IllegalArgumentException> {
            Json.decodeFromString<SdJwtTypeMetadataClaimInformationPath>("""["degrees", $tooBig]""")
        }
    }
}
