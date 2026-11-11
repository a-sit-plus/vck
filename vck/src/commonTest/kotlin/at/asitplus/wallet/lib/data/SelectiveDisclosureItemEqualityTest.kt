package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.orNull
import io.kotest.property.arbitrary.string
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive

/**
 * Regression tests for the `equals` and `hashCode` contract of [SelectiveDisclosureItem]: it was a class with a
 * `ByteArray` salt and hand-written `equals` and `hashCode` comparing the salt's content, and is a data class with the
 * salt as a string now (RFC 9901, 4.2.1), so equal fields have to keep making equal items with equal hash codes.
 */
val SelectiveDisclosureItemEqualityTest by matrixSuite {
    val items = Arb.bind(
        Arb.string(0..24),
        Arb.string(0..12).orNull(),
        Arb.string(0..24),
    ) { salt, claimName, claimValue -> SelectiveDisclosureItem(salt, claimName, JsonPrimitive(claimValue)) }

    "items with equal fields are equal, with equal hash codes" - {
        property(items, iterations = 256) test { item ->
            val other = SelectiveDisclosureItem(item.salt, item.claimName, item.claimValue)

            other shouldBe item
            item shouldBe other
            other.hashCode() shouldBe item.hashCode()
        }
    }

    "items differ in each field" - {
        property(items, iterations = 256) test { item ->
            val others = listOf(
                item.copy(salt = item.salt + "x"),
                item.copy(claimName = (item.claimName ?: "") + "x"),
                item.copy(claimValue = JsonArray(listOf(item.claimValue))),
            )

            others.forEach {
                it shouldNotBe item
                item shouldNotBe it
            }
        }
    }

    "salts of equal bytes make equal items, as their base64url strings" - {
        property(Arb.byteArray(Arb.int(0..32), Arb.byte()), iterations = 256) test { salt ->
            val claimValue = JsonPrimitive("value")
            val fromCopy = SelectiveDisclosureItem(salt.copyOf(), "name", claimValue)

            val fromBytes = SelectiveDisclosureItem(salt, "name", claimValue)

            fromBytes shouldBe fromCopy
            fromBytes.hashCode() shouldBe fromCopy.hashCode()
            fromBytes shouldBe SelectiveDisclosureItem(salt.encodeToString(Base64UrlStrict), "name", claimValue)
        }
    }

    "a missing claim name, as for an array element, differs from an empty one" {
        val arrayElement = SelectiveDisclosureItem("salt", null, JsonPrimitive("value"))

        val emptyName = SelectiveDisclosureItem("salt", "", JsonPrimitive("value"))

        emptyName shouldNotBe arrayElement
    }

    "salts are compared exactly as in the disclosure, not as the bytes they may encode" {
        val unpadded = SelectiveDisclosureItem("AA", "name", JsonPrimitive("value"))

        val padded = SelectiveDisclosureItem("AA==", "name", JsonPrimitive("value"))

        padded shouldNotBe unpadded
    }
}
