package at.asitplus.wallet.lib.iso

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Test correct appending tag 0 (in hex `C0`) for certain data elements,
 * as defined by ISO/IEC 18013-5:2021
 */
@OptIn(ExperimentalSerializationApi::class)
class Tag0SerializationTest : FreeSpec({

    "ValidityInfo" {
        val input = ValidityInfo(
            signed = Clock.System.now(),
            validFrom = Clock.System.now(),
            validUntil = Clock.System.now(),
            expectedUpdate = Clock.System.now(),
        )

        val serialized = vckCborSerializer.encodeToByteArray(input)
            .also { println(it.encodeToString(Base16(true))) }

        val text = "78" // COSE "text" for text value, i.e. the serialized Instant
        val tag0 = "C0$text" // COSE tag 0 plus "text"
        val hexEncoded = serialized.encodeToString(Base16(true))
        hexEncoded.shouldContain("7369676E6564$tag0") // "signed"<tag><text>
        hexEncoded.shouldContain("76616C696446726F6D$tag0") // "validFrom"<tag><text>
        hexEncoded.shouldContain("76616C6964556E74696C$tag0") // "validUntil"<tag><text>
        hexEncoded.shouldContain("6578706563746564557064617465$tag0") // "expectedUpdate"<tag><text>
        vckCborSerializer.decodeFromByteArray<ValidityInfo>(serialized) shouldBe input
    }

})
