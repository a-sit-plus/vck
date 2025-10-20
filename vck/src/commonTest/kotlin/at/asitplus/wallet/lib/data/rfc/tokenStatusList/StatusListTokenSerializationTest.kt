package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.extensions.toView
import de.infix.testBalloon.framework.testSuite
import at.asitplus.testballoon.*
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlin.time.Instant
import kotlinx.serialization.json.Json
import kotlin.time.DurationUnit
import kotlin.time.toDuration


val StatusListTokenSerializationTest by testSuite{
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
                            it.statusList.statusBitSize shouldBe TokenStatusBitSize.ONE
                        },
                        "statuslist status" to {
                            it.statusList.toView()[0u] shouldBe TokenStatus(1u)
                        },
                    ),
                ),
            ),
        )
    "jwt status list token payload" - {
        "deserialization" - {
            withData(
                jsonStatusListTokenPayloadTestVectors
            ) { (it, assertions) ->
                val value = Json.decodeFromString<StatusListTokenPayload>(it)
                withData(assertions) {
                    it(value)
                }
                Json.decodeFromString<StatusListTokenPayload>(Json.encodeToString(value)) shouldBe value
                val value2 = Json.decodeFromString<StatusListTokenPayload>(Json.encodeToString(value))
                value2.statusList shouldBe value.statusList
                value2.timeToLive shouldBe value.timeToLive
                value2.subject shouldBe value.subject
                value2.expirationTime shouldBe value.expirationTime
                value2.issuedAt shouldBe value.issuedAt
                value2 shouldBe value
            }
        }
    }
}