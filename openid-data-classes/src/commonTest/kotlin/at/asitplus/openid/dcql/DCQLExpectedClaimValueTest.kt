package at.asitplus.openid.dcql

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json

val DCQLExpectedClaimValueTest by matrixSuite {
    "serialization" - {
        listOf("-1", "0", "1", "false", "true", "other").asData() test {
            Json.decodeFromString<DCQLExpectedClaimValue>(Json.encodeToString(it))
                .shouldBeInstanceOf<DCQLExpectedClaimValue.StringValue>()
        }

        listOf("0", "1", "-1").asData() test {
            Json.decodeFromString<DCQLExpectedClaimValue>(it).shouldBeInstanceOf<DCQLExpectedClaimValue.IntegerValue>()
        }

        listOf("true", "false").asData() test {
            Json.decodeFromString<DCQLExpectedClaimValue>(it).shouldBeInstanceOf<DCQLExpectedClaimValue.BooleanValue>()
        }
    }
}