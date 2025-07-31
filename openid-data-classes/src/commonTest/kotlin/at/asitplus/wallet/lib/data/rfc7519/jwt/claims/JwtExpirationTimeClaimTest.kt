package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.time.DurationUnit
import kotlin.time.toDuration

class JwtExpirationTimeClaimTest : FreeSpec({
    "specification robustness" {
        JwtExpirationTimeClaim.Specification.CLAIM_NAME shouldBe "exp"
    }
    "validation" - {
        val now = Clock.System.now()
        withData(
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
})