package at.asitplus.wallet.lib.agent

import at.asitplus.catching
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CredentialChecks
import at.asitplus.wallet.lib.validation.CredentialValidationContext
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.input
import at.asitplus.wallet.lib.validation.issuance
import at.asitplus.wallet.lib.validation.scheme
import at.asitplus.wallet.lib.validation.strictPolicy
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val HolderAgentProofKeysTest by matrixSuite {

    listOf(CredentialRepresentation.PLAIN_JWT, CredentialRepresentation.SD_JWT, CredentialRepresentation.ISO_MDOC)
        .asData(nameFn = { "$it" }) - { representation ->

            "a credential bound to one of the proof keys is stored by a holder with a resolver" {
                val issuance = issuance()
                val otherKey = EphemeralKeyWithoutCert()
                val holder = HolderAgent(
                    holderKeyResolver = resolverOf(issuance.holderKey, otherKey),
                    credentialValidator = issuance.validator(),
                )

                val prepared = holder.prepareCredentialStorage(
                    input = issuance.issue(representation).input(),
                    scheme = scheme,
                    policy = strictPolicy,
                    expectedHolderKeys = setOf(otherKey.publicKey, issuance.holderKey.publicKey),
                ).getOrThrow()

                prepared.validation.report.decision shouldBe ACCEPTED
                prepared.holderKey shouldBe issuance.holderKey.publicKey
                holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldNotBeNull()
                holder.getCredentials().shouldNotBeNull().shouldHaveSize(1)
            }

            "a credential bound to no proof key is rejected and can't be stored" {
                val issuance = issuance()
                val otherKey = EphemeralKeyWithoutCert()
                val holder = HolderAgent(
                    holderKeyResolver = resolverOf(issuance.holderKey, otherKey),
                    credentialValidator = issuance.validator(),
                )

                val prepared = holder.prepareCredentialStorage(
                    input = issuance.issue(representation).input(),
                    scheme = scheme,
                    policy = strictPolicy,
                    expectedHolderKeys = setOf(otherKey.publicKey),
                ).getOrThrow()

                prepared.validation.report.checks.shouldBeInstanceOf<CredentialChecks>().holderBinding
                    .shouldBeInstanceOf<CheckOutcome.Failed>()
                holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldBeNull()
                holder.storeAfterUserConsent(prepared).isFailure shouldBe true
                holder.getCredentials().shouldNotBeNull().shouldBeEmpty()
            }

            "without proof keys, the holder binding of a holder with a resolver is blocked" {
                val issuance = issuance()
                val holder = HolderAgent(
                    holderKeyResolver = resolverOf(issuance.holderKey),
                    credentialValidator = issuance.validator(),
                )

                val prepared = holder.prepareCredentialStorage(issuance.issue(representation).input(), scheme, strictPolicy)
                    .getOrThrow()

                prepared.validation.report.checks.shouldBeInstanceOf<CredentialChecks>().holderBinding
                    .shouldBeInstanceOf<CheckOutcome.Blocked>()
                holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldBeNull()
            }

            "without proof keys, a holder with one key expects that key, as before" {
                val issuance = issuance()
                val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.validator())

                val prepared = holder.prepareCredentialStorage(issuance.issue(representation).input(), scheme, strictPolicy)
                    .getOrThrow()

                prepared.validation.report.decision shouldBe ACCEPTED
                holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldNotBeNull()
            }

            "a credential whose key has been deleted since its preparation is not stored" {
                val issuance = issuance()
                var known = true
                val holder = HolderAgent(
                    holderKeyResolver = HolderKeyResolver { bound ->
                        catching {
                            check(known) { "Deleted" }
                            issuance.holderKey.also { require(it.publicKey == bound) }
                        }
                    },
                    credentialValidator = issuance.validator(),
                )
                val prepared = holder.prepareCredentialStorage(
                    input = issuance.issue(representation).input(),
                    scheme = scheme,
                    policy = strictPolicy,
                    expectedHolderKeys = setOf(issuance.holderKey.publicKey),
                ).getOrThrow()

                known = false

                holder.storeAccepted(prepared).isFailure shouldBe true
                holder.getCredentials().shouldNotBeNull().shouldBeEmpty()
            }
        }

    "the expected keys of a validation context include the deprecated single expected key" {
        val first = EphemeralKeyWithoutCert().publicKey
        val second = EphemeralKeyWithoutCert().publicKey

        CredentialValidationContext(expectedHolderKey = first, expectedHolderKeys = setOf(second))
            .allExpectedHolderKeys shouldBe setOf(first, second)
    }
}

private fun resolverOf(vararg keys: KeyMaterial) = HolderKeyResolver { bound ->
    catching { keys.first { it.publicKey == bound } }
}
