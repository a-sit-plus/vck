package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.time.DurationUnit
import kotlin.time.toDuration

@ExperimentalUnsignedTypes
class StatusListTokenSerializationTest : FreeSpec({
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
                            it.subject.toString() shouldBe "https://example.com/statuslists/1"
                        },
                        "ttl consistency" to {
                            it.timeToLive!!.duration shouldBe 43200.toDuration(DurationUnit.SECONDS)
                        },
                        "iat consistency" to {
                            it.issuedAt.secondsSinceEpoch - 1686920170 shouldBe 0
                        },
                        "exp consistency" to {
                            it.expirationTime!!.secondsSinceEpoch - 2291720170 shouldBe 0
                        },
                        "statuslist bitsize" to {
                            it.statusList.statusBitSize shouldBe TokenStatusBitSize.ONE
                        },
                        "statuslist status" to {
                            it.statusList[0] shouldBe TokenStatus(1u)
                        },
                    ),
                ),
            ),
        )
    "jwt status list token payload" - {
        "deserialization" - {
            withData(
                data = jsonStatusListTokenPayloadTestVectors
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
//    "deserialization" - {
//        val testData = mapOf(
//            Cbor to mapOf(
//                "draft-section-5.2-9" to "d28453a20126106e7374617475736c6973742b637774a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f7374617475736c697374732f31061a648c5bea041a8898dfea19fffe19a8c019fffda2646269747301636c73744a78dadbb918000217015d5840b1a82166ee24aeb1a4411cd1a3fafb64dc989ebbb59be36964063f3ca137bf1757ef4e4c7637f2a070167e26fa561e22b94347d5e798944016c8e4f018bcac4a",
//            )
//        )
//        withData(
//            testData.keys
//        ) {
//            withData(
//                testData[it]!!
//            ) {
//                Cbor.decodeFromHexString<CborWebToken>(it) shouldBe true
//                Cbor.decodeFromHexString<StatusListToken>(it) shouldBe true
//                Cbor {
//                    this.preferCborLabelsOverNames = true
//                }.encodeToHexString(
//                    CwtStatusListToken.Data(
//                        typ = "statuslist+cwt",
//                        iat = NumericDate.fromInstant(Clock.System.now()),
//                        exp = NumericDate.fromInstant(Clock.System.now()),
//                        sub = StringOrURI("Subject 123"),
//                        status_list = StatusList.fromTokenStatuses(
//                            TokenStatus.TokenStatus1(0),
//                            TokenStatus.TokenStatus1(0),
//                            TokenStatus.TokenStatus1(0),
//                            TokenStatus.TokenStatus1(0),
//                            TokenStatus.TokenStatus1(0),
//                            TokenStatus.TokenStatus1(0),
//                            TokenStatus.TokenStatus1(0),
//                            TokenStatus.TokenStatus1(0),
//                            TokenStatus.TokenStatus1(0),
//                            TokenStatus.TokenStatus1(0),
//                        )
//                    )
//                ) shouldBe "test"
//            }
//        }
//    }
})