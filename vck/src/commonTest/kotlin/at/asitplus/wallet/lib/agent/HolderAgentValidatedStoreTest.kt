package at.asitplus.wallet.lib.agent

import at.asitplus.openid.OpenId4VciClaimsPathPointer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CredentialChecks
import at.asitplus.wallet.lib.validation.CredentialValidationInput
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.RequiredClaim
import at.asitplus.wallet.lib.validation.RequiredClaims
import at.asitplus.wallet.lib.validation.RequiredClaimsPolicy
import at.asitplus.wallet.lib.validation.StatusValidator
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import at.asitplus.wallet.lib.validation.input
import at.asitplus.wallet.lib.validation.issuance
import at.asitplus.wallet.lib.validation.scheme
import at.asitplus.wallet.lib.validation.strictPolicy
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.encodeToByteArray

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
                    val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.untrustingValidator())
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

                "a rejected but intact credential is stored only after the user's consent" {
                    val issuance = issuance()
                    val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.untrustingValidator())
                    val prepared = holder.prepareCredentialStorage(
                        issuance.issue(representation).toStoreCredentialInput(),
                        strictPolicy,
                    ).getOrThrow()

                    prepared.validation.report.decision shouldBe REJECTED
                    holder.getCredentials().shouldNotBeNull().shouldBeEmpty()
                    holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldBeNull()
                    holder.getCredentials().shouldNotBeNull().shouldBeEmpty()

                    holder.storeAfterUserConsent(prepared).getOrThrow().let {
                        it.validation shouldBe prepared.validation
                        it.storedEntry.shouldNotBeNull()
                    }
                    holder.getCredentials().shouldNotBeNull().shouldHaveSize(1)
                }

                "a credential missing required claims is stored only after the user's consent" {
                    val issuance = issuance()
                    val validator = CredentialValidator(
                        trustAnchors = issuance.trustAnchors,
                        statusValidator = StatusValidator(issuance.statusTokens),
                        requiredClaimsResolver = { identifier, _ ->
                            RequiredClaims(identifier, listOf(RequiredClaim(OpenId4VciClaimsPathPointer("missing"))))
                        },
                    )
                    val holder = HolderAgent(issuance.holderKey, credentialValidator = validator)
                    val prepared = holder.prepareCredentialStorage(
                        issuance.issue(representation).toStoreCredentialInput(),
                        strictPolicy.copy(requiredClaims = RequiredClaimsPolicy.RequireMandatory),
                    ).getOrThrow()

                    prepared.validation.report.checks.shouldBeInstanceOf<CredentialChecks>().requiredClaims.outcome
                        .shouldBeInstanceOf<CheckOutcome.Failed>()
                    holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldBeNull()
                    holder.storeAfterUserConsent(prepared).getOrThrow().storedEntry.shouldNotBeNull()
                }

                "a credential bound to another key can not be stored, even after the user's consent" {
                    val issuance = issuance()
                    val holder = HolderAgent(EphemeralKeyWithoutCert(), credentialValidator = issuance.validator())
                    val prepared = holder.prepareCredentialStorage(
                        issuance.issue(representation).toStoreCredentialInput(),
                        strictPolicy,
                    ).getOrThrow()

                    prepared.validation.unacceptedCredential.shouldBeNull()
                    holder.storeAfterUserConsent(prepared).isFailure shouldBe true
                    holder.getCredentials().shouldNotBeNull().shouldBeEmpty()
                }

                "a credential prepared by another holder is not stored" {
                    val issuance = issuance()
                    val prepared = HolderAgent(issuance.holderKey, credentialValidator = issuance.validator())
                        .prepareCredentialStorage(issuance.issue(representation).toStoreCredentialInput(), strictPolicy)
                        .getOrThrow()
                    val other = HolderAgent(EphemeralKeyWithoutCert(), credentialValidator = issuance.validator())

                    other.storeAccepted(prepared).isFailure shouldBe true
                    other.storeAfterUserConsent(prepared).isFailure shouldBe true
                    other.getCredentials().shouldNotBeNull().shouldBeEmpty()
                }

                "the legacy store fails with the cause of the rejection, and stores nothing" {
                    val issuance = issuance()
                    val untrusted =
                        HolderAgent(issuance.holderKey, credentialValidator = issuance.untrustingValidator())

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

    "preparing an encoded credential" - {
        listOf(CredentialRepresentation.PLAIN_JWT, CredentialRepresentation.SD_JWT, CredentialRepresentation.ISO_MDOC)
            .asData(nameFn = { "$it" }) - { representation ->

                "an accepted credential is stored as it has been validated" {
                    val issuance = issuance()
                    val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.validator())
                    val input = issuance.issue(representation).input()
                    val prepared = holder.prepareCredentialStorage(input, scheme, strictPolicy).getOrThrow()

                    prepared.validation.report.decision shouldBe ACCEPTED
                    prepared.credential.shouldNotBeNull()
                    val stored = holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldNotBeNull()
                    holder.getCredentials().shouldNotBeNull().shouldHaveSize(1)
                    when (stored) {
                        is SubjectCredentialStore.StoreEntry.Vc -> stored.vcSerialized shouldBe
                                input.shouldBeInstanceOf<CredentialValidationInput.VcJwt>().compact

                        is SubjectCredentialStore.StoreEntry.SdJwt -> stored.vcSerialized shouldBe
                                input.shouldBeInstanceOf<CredentialValidationInput.SdJwtVc>().compact

                        // The stored mdoc is the one decoded from the issuer's bytes, so presentations carry them
                        is SubjectCredentialStore.StoreEntry.Iso ->
                            coseCompliantSerializer.encodeToByteArray(stored.issuerSigned) shouldBe
                                    input.shouldBeInstanceOf<CredentialValidationInput.IsoMdoc>().issuerSignedCbor
                    }
                }

                "a rejected but intact credential is stored only after the user's consent" {
                    val issuance = issuance()
                    val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.untrustingValidator())
                    val input = issuance.issue(representation).input()
                    val prepared = holder.prepareCredentialStorage(input, scheme, strictPolicy).getOrThrow()

                    prepared.validation.report.decision shouldBe REJECTED
                    prepared.credential.shouldNotBeNull()
                    holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldBeNull()
                    holder.storeAfterUserConsent(prepared).getOrThrow().storedEntry.shouldNotBeNull()
                    holder.getCredentials().shouldNotBeNull().shouldHaveSize(1)
                }

                "a credential bound to another key has nothing to store, even after the user's consent" {
                    val issuance = issuance()
                    val holder = HolderAgent(EphemeralKeyWithoutCert(), credentialValidator = issuance.validator())
                    val input = issuance.issue(representation).input()
                    val prepared = holder.prepareCredentialStorage(input, scheme, strictPolicy).getOrThrow()

                    prepared.validation.report.checks.shouldBeInstanceOf<CredentialChecks>().holderBinding
                        .shouldBeInstanceOf<CheckOutcome.Failed>()
                    prepared.credential.shouldBeNull()
                    holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldBeNull()
                    holder.storeAfterUserConsent(prepared).isFailure shouldBe true
                    holder.getCredentials().shouldNotBeNull().shouldBeEmpty()
                }
            }

        "a credential of another type than its scheme is rejected" {
            val issuance = issuance()
            val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.validator())
            val prepared = holder.prepareCredentialStorage(
                issuance.issue(CredentialRepresentation.SD_JWT).input(),
                OtherSdJwtScheme,
                strictPolicy,
            ).getOrThrow()

            prepared.validation.report.checks.shouldBeInstanceOf<CredentialChecks>().semantics
                .shouldBeInstanceOf<CheckOutcome.Failed>()
            holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldBeNull()
        }

        "a scheme without the representation of the credential fails" {
            val issuance = issuance()
            val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.validator())

            holder.prepareCredentialStorage(
                issuance.issue(CredentialRepresentation.ISO_MDOC).input(),
                OtherSdJwtScheme,
                strictPolicy,
            ).isFailure shouldBe true
        }

        "an undecodable credential is rejected, and can never be stored" {
            val issuance = issuance()
            val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.validator())
            val prepared = holder.rejectUndecodable(IllegalArgumentException("not base64url"), strictPolicy)

            prepared.validation.report.decision shouldBe REJECTED
            prepared.validation.report.checks.shouldBeInstanceOf<CredentialChecks>().parsing
                .shouldBeInstanceOf<CheckOutcome.Failed>()
            prepared.credential.shouldBeNull()
            holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldBeNull()
            holder.storeAfterUserConsent(prepared).isFailure shouldBe true
            holder.getCredentials().shouldNotBeNull().shouldBeEmpty()
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
