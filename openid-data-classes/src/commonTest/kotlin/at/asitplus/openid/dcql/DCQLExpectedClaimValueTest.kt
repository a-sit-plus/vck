package at.asitplus.openid.dcql

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json

val DCQLExpectedClaimValueTest by matrixSuite {
    "serialization" - {
        data(listOf("-1", "0", "1", "false", "true", "other")) test {
            Json.decodeFromString<DCQLExpectedClaimValue>(Json.encodeToString(it))
                .shouldBeInstanceOf<DCQLExpectedClaimValue.StringValue>()
        }

        data(listOf("0", "1", "-1")) test {
            Json.decodeFromString<DCQLExpectedClaimValue>(it).shouldBeInstanceOf<DCQLExpectedClaimValue.IntegerValue>()
        }

        data(listOf("true", "false")) test {
            Json.decodeFromString<DCQLExpectedClaimValue>(it).shouldBeInstanceOf<DCQLExpectedClaimValue.BooleanValue>()
        }
    }
}