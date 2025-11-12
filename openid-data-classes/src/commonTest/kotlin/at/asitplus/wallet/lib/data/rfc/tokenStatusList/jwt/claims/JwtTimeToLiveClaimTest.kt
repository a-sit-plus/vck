package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.DurationUnit
import kotlin.time.Instant
import kotlin.time.toDuration

val JwtTimeToLiveClaimTest by testSuite {
    "specification robustness" {
        JwtTimeToLiveClaim.Specification.CLAIM_NAME shouldBe "ttl"
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
            withDataSuites(
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
                        JwtTimeToLiveClaim(it)
                        true
                    } catch (_: IllegalArgumentException) {
                        false
                    } shouldBe isValid
                }
            }
        }


        withDataSuites(
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
                JwtTimeToLiveClaim(it.second).isInvalid(
                    resolvedAt = it.first,
                    isInstantInThePast = {
                        it < now
                    }
                ) shouldBe !isValid
            }
        }
    }
}