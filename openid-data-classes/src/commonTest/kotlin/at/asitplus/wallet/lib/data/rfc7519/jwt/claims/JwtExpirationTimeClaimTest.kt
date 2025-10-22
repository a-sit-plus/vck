package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import kotlin.time.Clock
import kotlin.time.DurationUnit
import kotlin.time.Instant
import kotlin.time.toDuration

val JwtExpirationTimeClaimTest by testSuite {
    "specification robustness" {
        JwtExpirationTimeClaim.Specification.CLAIM_NAME shouldBe "exp"
    }
    "validation" - {
        val now = Clock.System.now()
        withDataSuites(
            mapOf<String, Pair<List<Instant>, Boolean>>(
                "past" to Pair(
                    listOf(
                        now.minus(1.0.toDuration(DurationUnit.SECONDS))
                    ),
                    false,
                ),
                "present" to Pair(
                    listOf(now),
                    true,
                ),
                "future" to Pair(
                    listOf(
                        now.plus(1.0.toDuration(DurationUnit.SECONDS))
                    ), true
                ),
            ),
        ) { (instants, isValid) ->
            withData(instants) {
                JwtExpirationTimeClaim(it).isInvalid {
                    it < now
                }  shouldBe !isValid
            }
        }
    }
}