package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.MediaType
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class MediaTypeSerializationTest : FreeSpec({
    "test" {
        Json.encodeToString(MediaType("test")) shouldBe Json.encodeToString("test")
    }
})