package at.asitplus.openid.dcql

import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json

val DCQLExpectedClaimValueTest by testSuite {
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
}