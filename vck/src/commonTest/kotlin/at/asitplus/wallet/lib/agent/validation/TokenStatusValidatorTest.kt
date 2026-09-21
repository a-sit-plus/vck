package at.asitplus.wallet.lib.agent.validation

import at.asitplus.KmmResult
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

private val statusListInfo = StatusListInfo(
    index = 1U,
    uri = UniformResourceIdentifier("https://example.com/statuslist.cwt"),
)

private val identifierListInfo = IdentifierListInfo(
    identifier = byteArrayOf(0x01),
    uri = UniformResourceIdentifier("https://example.com/identifierlist.cwt"),
)

private val multipleStatusMechanisms = TokenStatusInfo(statusListInfo, identifierListInfo)

val TokenStatusValidatorTest by matrixSuite {
    "all status mechanisms must be valid" {
        val validator = TokenStatusValidator { TokenStatusValidationResult.Valid(TokenStatus.Valid) }

        validator(multipleStatusMechanisms) shouldBe TokenStatusValidationResult.Valid(TokenStatus.Valid)
    }

    "an invalid status mechanism dominates a resolution failure" {
        val resolutionFailure = IllegalStateException("unavailable")
        val validator = TokenStatusValidator {
            when (it) {
                is StatusListInfo -> TokenStatusValidationResult.Rejected(resolutionFailure)
                is IdentifierListInfo -> TokenStatusValidationResult.Invalid(TokenStatus.Invalid)
            }
        }

        validator(multipleStatusMechanisms) shouldBe TokenStatusValidationResult.Invalid(TokenStatus.Invalid)
    }

    "a resolution failure rejects otherwise valid status information" {
        val resolutionFailure = IllegalStateException("unavailable")
        val validator = TokenStatusValidator {
            when (it) {
                is StatusListInfo -> TokenStatusValidationResult.Valid(TokenStatus.Valid)
                is IdentifierListInfo -> TokenStatusValidationResult.Rejected(resolutionFailure)
            }
        }

        validator(multipleStatusMechanisms) shouldBe TokenStatusValidationResult.Rejected(resolutionFailure)
    }

    "conflicting valid mechanism results are rejected" {
        val validator = TokenStatusValidator {
            TokenStatusValidationResult.Valid(
                when (it) {
                    is StatusListInfo -> TokenStatus.Valid
                    is IdentifierListInfo -> TokenStatus.Suspended
                }
            )
        }

        validator(multipleStatusMechanisms)
            .shouldBeInstanceOf<TokenStatusValidationResult.Rejected>()
    }

    "status resolver rejects conflicting mechanism results" {
        val resolver = TokenStatusResolver {
            KmmResult.success(
                when (it) {
                    is StatusListInfo -> TokenStatus.Valid
                    is IdentifierListInfo -> TokenStatus.Invalid
                }
            )
        }

        shouldThrow<IllegalArgumentException> {
            resolver(multipleStatusMechanisms).getOrThrow()
        }
    }

    "status resolver returns the common mechanism result" {
        val resolver = TokenStatusResolver { KmmResult.success(TokenStatus.Valid) }

        resolver(multipleStatusMechanisms).getOrThrow() shouldBe TokenStatus.Valid
    }
}
