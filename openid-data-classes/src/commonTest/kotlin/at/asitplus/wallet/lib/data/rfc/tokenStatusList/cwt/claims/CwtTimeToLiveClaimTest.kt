package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims

import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.time.Duration
import kotlin.time.DurationUnit
import kotlin.time.toDuration

class CwtTimeToLiveClaimTest : FreeSpec({
    "specification robustness" {
        CwtTimeToLiveClaim.Specification.CLAIM_NAME shouldBe "ttl"
        CwtTimeToLiveClaim.Specification.CLAIM_KEY shouldBe 65534L
    }
    "validation" - {
        val oneSecond = 1.0.toDuration(DurationUnit.SECONDS)
        val oneMinute = 1.0.toDuration(DurationUnit.MINUTES)
        val oneHour = 1.0.toDuration(DurationUnit.HOURS)

        val now = Clock.System.now()

        val oneSecondAgo = now.minus(oneSecond)
        val oneMinuteAgo = now.minus(oneMinute)
        val oneHourAgo = now.minus(oneHour)

        val inOneSecond = now.plus(oneSecond)
        val inOneMinute = now.plus(oneMinute)
        val inOneHour = now.plus(oneHour)

        "value" - {
            withData(
                mapOf<String, Pair<List<Duration>, Boolean>>(
                    "negative duration" to Pair(
                        listOf(
                            -oneHour,
                            -oneMinute,
                            -oneSecond,
                        ),
                        false,
                    ),
                    "zero duration" to Pair(
                        listOf(
                            Duration.ZERO,
                        ),
                        false,
                    ),
                    "positive duration" to Pair(
                        listOf(
                            oneSecond,
                            oneMinute,
                            oneHour,
                        ),
                        true,
                    ),
                ),
            ) { (durations, isValid) ->
                withData(durations) {
                    try {
                        CwtTimeToLiveClaim(it)
                        true
                    } catch (_: IllegalArgumentException) {
                        false
                    } shouldBe isValid
                }
            }
        }


        withData(
            mapOf<String, Pair<List<Pair<Instant, Duration>>, Boolean>>(
                "past to past" to Pair(
                    listOf(
                        oneHourAgo to oneSecond,
                        oneHourAgo to oneMinute,
                        oneMinuteAgo to oneSecond,
                    ),
                    false,
                ),
                "past to present" to Pair(
                    listOf(
                        oneSecondAgo to oneSecond,
                        oneMinuteAgo to oneMinute,
                        oneHourAgo to oneHour,
                    ),
                    true,
                ),
                "past to future" to Pair(
                    listOf(
                        oneMinuteAgo to oneHour,
                        oneSecondAgo to oneMinute,
                        oneSecondAgo to oneHour,
                    ),
                    true,
                ),
                "present to future" to Pair(
                    listOf(
                        now to oneSecond,
                        now to oneMinute,
                        now to oneHour,
                    ),
                    true,
                ),
            ),
        ) { (resolvedAtWithTimeToLive, isValid) ->
            withData(resolvedAtWithTimeToLive) {
                CwtTimeToLiveClaim(it.second).isInvalid(
                    resolvedAt = it.first,
                    isInstantInThePast = {
                        it < now
                    }
                ) shouldBe !isValid
            }
        }
    }
})