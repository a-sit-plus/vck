package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.data.Base64UrlStrict
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.ktor.util.encodeBase64
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random

class SdJwtSerializationTest : FreeSpec({

    "Serialization is correct" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = Random.nextBytes(16).encodeToString(Base64())
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = item.serialize()
        println(serialized)

        serialized shouldContain "["
        serialized shouldContain """"${salt.encodeToString(Base64UrlStrict)}""""
        serialized shouldContain """"${name}""""
        serialized shouldContain """"${value}""""
        serialized shouldContain "]"

        val deserialized = SelectiveDisclosureItem.deserialize(serialized)
        deserialized shouldBe item
    }

})
