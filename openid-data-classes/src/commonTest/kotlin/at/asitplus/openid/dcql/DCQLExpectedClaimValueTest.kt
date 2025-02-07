package at.asitplus.openid.dcql

import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class DCQLExpectedClaimValueTest : FreeSpec({
    "serialization" - {
        withData(
            "-1", "0", "1", "false", "true", "other"
        ) {
            Json.decodeFromString<DCQLExpectedClaimValue>(Json.encodeToString(it))
                .shouldBeInstanceOf<DCQLExpectedClaimValue.StringValue>()
        }

        withData(
            "0", "1", "-1"
        ) {
            Json.decodeFromString<DCQLExpectedClaimValue>(it).shouldBeInstanceOf<DCQLExpectedClaimValue.IntegerValue>()
        }

        withData(
            "true", "false"
        ) {
            Json.decodeFromString<DCQLExpectedClaimValue>(it).shouldBeInstanceOf<DCQLExpectedClaimValue.BooleanValue>()
        }
    }
})