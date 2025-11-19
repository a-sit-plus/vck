package at.asitplus.wallet.lib.data.iso18013

import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.data.Status
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.cbor.Cbor

private val cbor = Cbor {
    ignoreUnknownKeys = true
    useDefiniteLengthEncoding = true
}

/**
 * From Annex D.7
 * {
 *   "identifier_list": {
 *     "id": h'cccc',
 *     "uri": "https://example.com/identifierlists/1",
 *     "certificate": h'aa'
 *   }
 * }
 *    A1                                   # map(1)
 *    6F                                   # text(15)
 *       6964656E7469666965725F6C697374    # "identifier_list"
 *    A3                                   # map(3)
 *       62                                # text(2)
 *          6964                           # "id"
 *       42                                # bytes(2)
 *          CCCC                           # "\xCC\xCC"
 *       63                                # text(3)
 *          757269                         # "uri"
 *       78 25                             # text(37)
 *          68747470733A2F2F6578616D706C652E636F6D2F6964656E7469666965726C697374732F31 # "https://example.com/identifierlists/1"
 *       6B                                # text(11)
 *          6365727469666963617465         # "certificate"
 *       41                                # bytes(1)
 *          AA                             # "\xAA"
 *
 */
val status_test_vec =
    "A16F6964656E7469666965725F6C697374A362696442CCCC63757269782568747470733A2F2F6578616D706C652E636F6D2F6964656E7469666965726C697374732F316B636572746966696361746541AA"

val IdentifierListTest by testSuite {
    "status can be decoded" {
        val actual = cbor.decodeFromByteArray(Status.serializer(), status_test_vec.decodeToByteArray(Base16Strict))
        val expected = Status(
            identifierList = IdentifierListInfo(
                identifier = byteArrayOf(0xcc.toByte(), 0xcc.toByte()),
                uri = "https://example.com/identifierlists/1",
                certificate = byteArrayOf(0xaa.toByte())
            )
        )
        val serialized = cbor.encodeToByteArray(Status.serializer(), expected)
        val deserialized = cbor.decodeFromByteArray(Status.serializer(), serialized)
        actual shouldBe expected
        deserialized shouldBe expected
        serialized.encodeToString(Base16Strict) shouldBe status_test_vec
    }
}
