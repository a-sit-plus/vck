package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.extensions.toView
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlin.time.DurationUnit
import kotlin.time.Instant
import kotlin.time.toDuration


val StatusListTokenSerializationTest by testSuite {
    val jsonStatusListTokenPayloadTestVectors =
        mapOf<String, Pair<String, Map<String, (StatusListTokenPayload) -> Unit>>>(
            Pair(
                "payload with all fields",
                Pair(
                    """
                    {   
                      "exp": 2291720170,
                      "iat": 1686920170,
                      "status_list": {
                        "bits": 1,
                        "lst": "eNrbuRgAAhcBXQ"
                      },
                      "sub": "https://example.com/statuslists/1",
                      "ttl": 43200
                    }""",
                    mapOf(
                        "sub consistent" to {
                            it.subject.string shouldBe "https://example.com/statuslists/1"
                        },
                        "ttl consistency" to {
                            it.timeToLive!!.duration shouldBe 43200.toDuration(DurationUnit.SECONDS)
                        },
                        "iat consistency" to {
                            it.issuedAt shouldBe Instant.fromEpochSeconds(1686920170)
                        },
                        "exp consistency" to {
                            it.expirationTime!! shouldBe Instant.fromEpochSeconds(2291720170)
                        },
                        "statuslist bitsize" to {
                            it.revocationList.shouldBeInstanceOf<StatusList>().statusBitSize shouldBe TokenStatusBitSize.ONE
                        },
                        "statuslist status" to {
                            it.revocationList.shouldBeInstanceOf<StatusList>().toView()[0u] shouldBe TokenStatus(1u)
                        },
                    ),
                ),
            ),
        )
    "jwt status list token payload" - {
        "deserialization" - {
            withDataSuites(
                jsonStatusListTokenPayloadTestVectors
            ) { (it, assertions) ->
                val value = Json.decodeFromString<StatusListTokenPayload>(it)
                withData(assertions) {
                    it(value)
                }
                Json.decodeFromString<StatusListTokenPayload>(Json.encodeToString(value)) shouldBe value
                val value2 = Json.decodeFromString<StatusListTokenPayload>(Json.encodeToString(value))
                value2.revocationList.shouldBeInstanceOf<StatusList>()
                value2.revocationList shouldBe value.revocationList
                value2.timeToLive shouldBe value.timeToLive
                value2.subject shouldBe value.subject
                value2.expirationTime shouldBe value.expirationTime
                value2.issuedAt shouldBe value.issuedAt
                value2 shouldBe value
            }
        }
    }
}