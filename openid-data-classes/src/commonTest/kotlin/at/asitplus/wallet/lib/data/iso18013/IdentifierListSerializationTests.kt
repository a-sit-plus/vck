package at.asitplus.wallet.lib.data.iso18013

import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.Identifier
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.IdentifierInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.IdentifierInfoKey
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

/**
 * From Annex D.7
 * {
 *   "identifier_list": {
 *     "id": h'cccc',
 *     "uri": "https://example.com/identifierlists/1",
 *     "certificate": h'aa'
 *   }
 * }
 */
private const val statusTestVec =
    "A16F6964656E7469666965725F6C697374A362696442CCCC63757269782568747470733A2F2F6578616D706C652E636F6D2F6964656E7469666965726C697374732F316B636572746966696361746541AA"

/**
 * Modified Testcase from Annex D.7
 * {
 * 	"identifiers": {
 * 		h'abcd': {},
 * 		h'aaaa': { "note": {} },
 * 		h'cccc': { 7: {} },
 * 	},
 * 	"aggregation_uri": "https://example.com/identifierlists/aggregation"
 * }
 */
private const val identifierListTestVec =
    "A26B6964656E74696669657273A342ABCDA042AAAAA1646E6F7465A042CCCCA107A06F6167677265676174696F6E5F757269782F68747470733A2F2F6578616D706C652E636F6D2F6964656E7469666965726C697374732F6167677265676174696F6E"

val IdentifierListTest by testSuite {
    "status containing IdentifierListInfo can be serialized" {
        val expected = RevocationListInfo.StatusSurrogate(
            identifierList = IdentifierListInfo(
                identifier = byteArrayOf(0xcc.toByte(), 0xcc.toByte()),
                uri = UniformResourceIdentifier("https://example.com/identifierlists/1"),
                certificate = byteArrayOf(0xaa.toByte())
            )
        )
        val deserialized = coseCompliantSerializer.decodeFromByteArray(
            RevocationListInfo.StatusSurrogate.serializer(),
            statusTestVec.decodeToByteArray(Base16Strict)
        )

        val serialized =
            coseCompliantSerializer.encodeToByteArray(RevocationListInfo.StatusSurrogate.serializer(), deserialized)
        deserialized shouldBe expected //sanity check
        serialized.encodeToString(Base16Strict) shouldBe statusTestVec
    }

    "Identifier is correct surrogate for type 2 bytearray" {
        val encoded = coseCompliantSerializer.encodeToByteArray(
            Identifier.serializer(),
            Identifier(byteArrayOf(0xcc.toByte(), 0xcc.toByte()))
        ).encodeToString(Base16Strict)
        encoded shouldBe "42CCCC"
    }

    "IdentifierList can be serialized" {
        val expected = IdentifierList(
            identifiers = mapOf(
                Identifier(byteArrayOf(0xab.toByte(), 0xcd.toByte())) to IdentifierInfo(),
                Identifier(byteArrayOf(0xaa.toByte(), 0xaa.toByte())) to IdentifierInfo(
                    mapOf(IdentifierInfoKey.KeyString("note") to null)
                ),
                Identifier(byteArrayOf(0xcc.toByte(), 0xcc.toByte())) to IdentifierInfo(
                    mapOf(IdentifierInfoKey.KeyInt(7) to null)
                ),
            ),
            aggregationUri = "https://example.com/identifierlists/aggregation"
        )
        val deserialized =
            coseCompliantSerializer.decodeFromByteArray(
                IdentifierList.serializer(),
                identifierListTestVec.decodeToByteArray(Base16Strict)
            )
        val serialized = coseCompliantSerializer.encodeToByteArray(IdentifierList.serializer(), deserialized)
        deserialized shouldBe expected //sanity check
        serialized.encodeToString(Base16Strict) shouldBe identifierListTestVec
    }
}
