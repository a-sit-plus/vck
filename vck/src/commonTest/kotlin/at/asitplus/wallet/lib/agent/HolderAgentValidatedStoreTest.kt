package at.asitplus.wallet.lib.agent

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CredentialChecks
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.StatusValidator
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import at.asitplus.wallet.lib.validation.issuance
import at.asitplus.wallet.lib.validation.strictPolicy
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val HolderAgentValidatedStoreTest by matrixSuite {

    "storing with a report" - {
        listOf(CredentialRepresentation.PLAIN_JWT, CredentialRepresentation.SD_JWT, CredentialRepresentation.ISO_MDOC)
            .asData(nameFn = { "$it" }) - { representation ->

                "an accepted credential is stored" {
                    val issuance = issuance()
                    val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.validator())
                    val result = holder.storeCredentialWithReport(
                        issuance.issue(representation).toStoreCredentialInput(),
                        strictPolicy,
                    ).getOrThrow()

                    result.validation.report.decision shouldBe ACCEPTED
                    result.storedEntry.shouldNotBeNull()
                    holder.getCredentials().shouldNotBeNull().shouldHaveSize(1)
                }

                "a rejected credential is a successful result, and is not stored" {
                    val issuance = issuance()
                    val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance().validator())
                    val result = holder.storeCredentialWithReport(
                        issuance.issue(representation).toStoreCredentialInput(),
                        strictPolicy,
                    ).getOrThrow()

                    result.validation.report.decision shouldBe REJECTED
                    result.storedEntry.shouldBeNull()
                    holder.getCredentials().shouldNotBeNull().shouldBeEmpty()
                }

                "a credential of another holder is rejected" {
                    val issuance = issuance()
                    val holder = HolderAgent(EphemeralKeyWithoutCert(), credentialValidator = issuance.validator())
                    val result = holder.storeCredentialWithReport(
                        issuance.issue(representation).toStoreCredentialInput(),
                        strictPolicy,
                    ).getOrThrow()

                    result.storedEntry.shouldBeNull()
                    result.validation.report.checks.shouldBeInstanceOf<CredentialChecks>().holderBinding
                        .shouldBeInstanceOf<CheckOutcome.Failed>()
                }

                "the legacy store fails with the cause of the rejection, and stores nothing" {
                    val issuance = issuance()
                    val untrusted = HolderAgent(issuance.holderKey, credentialValidator = issuance().validator())

                    untrusted.storeCredential(issuance.issue(representation).toStoreCredentialInput())
                        .isFailure shouldBe true
                    untrusted.getCredentials().shouldNotBeNull().shouldBeEmpty()
                }

                "the legacy store without trust configured checks integrity only, as before" {
                    val issuance = issuance()
                    val holder = HolderAgent(issuance.holderKey)

                    holder.storeCredential(issuance.issue(representation).toStoreCredentialInput()).getOrThrow()
                    holder.getCredentials().shouldNotBeNull().shouldHaveSize(1)
                }
            }
    }

    "a credential of another type than its scheme is rejected" {
        val issuance = issuance()
        val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.validator())
        val input = issuance.issue(CredentialRepresentation.SD_JWT).toStoreCredentialInput()
            .shouldBeInstanceOf<Holder.StoreCredentialInput.SdJwt>()
            .copy(scheme = OtherSdJwtScheme)

        holder.storeCredentialWithReport(input, strictPolicy).getOrThrow().let {
            it.storedEntry.shouldBeNull()
            it.validation.report.checks.shouldBeInstanceOf<CredentialChecks>().semantics
                .shouldBeInstanceOf<CheckOutcome.Failed>()
        }
    }

    "trusted issuers and a credential validator are exclusive" {
        shouldThrow<IllegalArgumentException> {
            @Suppress("DEPRECATION")
            HolderAgent(
                keyMaterial = EphemeralKeyWithoutCert(),
                trustedIssuers = TrustedCertificates { emptySet() },
                credentialValidator = CredentialValidator(statusValidator = StatusValidator()),
            )
        }
    }
}

private object OtherSdJwtScheme : SdJwtCredentialScheme {
    override val sdJwtType = "urn:example:other:1"
}
