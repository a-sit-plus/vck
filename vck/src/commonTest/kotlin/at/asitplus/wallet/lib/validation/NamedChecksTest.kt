package at.asitplus.wallet.lib.validation

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import at.asitplus.wallet.lib.validation.Requirement.*
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

private val credentialChecks = CredentialChecks(
    parsing = Passed,
    issuerSignature = Passed,
    issuerTrust = trusted,
    semantics = Passed,
    disclosedItems = listOf(
        DisclosedItemValidation(DisclosedItemReference.SdJwt(0, "given_name"), Passed, Passed, Passed)
    ),
    holderBinding = NotApplicable,
    timeliness = TimelinessValidation(Passed, details = null),
    status = validStatus,
)

private val relaxedPolicy = strictPolicy.copy(
    trust = TrustPolicy.IntegrityOnly,
    status = ifPresent,
    requireTimeliness = false,
)

private fun List<NamedCheck>.requirements() = associate { it.name to it.requirement }

/** The named checks of a credential report with [this] checks under [policy]. */
private fun CredentialChecks.namedUnder(policy: ValidationPolicy) =
    ValidationReport.credential(this, policy, evaluatedAt).namedChecks

val NamedChecksTest by matrixSuite {

    "credential checks are listed in declaration order with their parts" {
        credentialChecks.namedUnder(strictPolicy).map { it.name } shouldBe listOf(
            "parsing",
            "issuerSignature",
            "issuerTrust",
            "semantics",
            "disclosedItems[0].parsing",
            "disclosedItems[0].digest",
            "disclosedItems[0].structure",
            "holderBinding",
            "timeliness",
            "status.claim",
            "status.mechanisms[0]",
            "status.agreement",
        )
    }

    "compound checks carry what they refer to" {
        val named = credentialChecks.namedUnder(strictPolicy).associateBy { it.name }
        named.getValue("issuerTrust").trust shouldBe trusted
        named.getValue("disclosedItems[0].digest").disclosedItem shouldBe DisclosedItemReference.SdJwt(0, "given_name")
        named.getValue("status.mechanisms[0]").statusMechanism shouldBe validStatus.mechanisms.single()
        named.getValue("parsing").trust.shouldBeNull()
    }

    "the policy relaxes trust and timeliness, never parsing or signatures" {
        val strict = credentialChecks
            .namedUnder(strictPolicy.copy(holderBinding = HolderBindingPolicy.RequireExpectedKey)).requirements()
        strict.getValue("issuerTrust") shouldBe REQUIRED
        strict.getValue("timeliness") shouldBe REQUIRED
        strict.getValue("holderBinding") shouldBe REQUIRED
        strict.getValue("status.claim") shouldBe REQUIRED

        val relaxed = credentialChecks.namedUnder(relaxedPolicy).requirements()
        relaxed.getValue("issuerTrust") shouldBe OPTIONAL
        relaxed.getValue("timeliness") shouldBe OPTIONAL
        relaxed.getValue("holderBinding") shouldBe OPTIONAL
        relaxed.getValue("status.claim") shouldBe REQUIRED_IF_APPLICABLE
        relaxed.getValue("parsing") shouldBe REQUIRED
        relaxed.getValue("issuerSignature") shouldBe REQUIRED
        relaxed.getValue("disclosedItems[0].digest") shouldBe REQUIRED
    }

    "a failed check tolerated by the policy is satisfied, and does not reject" {
        val expired = TimelinessException("expired", evaluatedAt, notBefore = null, notAfter = evaluatedAt)
        val checks = credentialChecks.copy(timeliness = TimelinessValidation(Failed(expired), details = null))

        val relaxed = ValidationReport.credential(checks, relaxedPolicy, evaluatedAt)
        relaxed.namedChecks.single { it.name == "timeliness" }.satisfied shouldBe true
        relaxed.decision shouldBe ACCEPTED

        val strict = ValidationReport.credential(checks, strictPolicy, evaluatedAt)
        strict.namedChecks.single { it.name == "timeliness" }.satisfied shouldBe false
        strict.firstRejection() shouldBe expired
    }

    "status parts count only for a claim that passed" {
        val withoutClaim = credentialChecks.copy(status = StatusValidation(NotApplicable, agreement = NotApplicable))
        withoutClaim.namedUnder(relaxedPolicy).filter { it.name.startsWith("status.") }
            .map { it.name to it.requirement } shouldBe listOf(
            "status.claim" to REQUIRED_IF_APPLICABLE,
            "status.agreement" to OPTIONAL,
        )

        val revoked = mechanism().copy(
            outcome = Failed(TokenStatusException(TokenStatus.Invalid)),
            observed = TokenStatus.Invalid,
        )
        val checks = credentialChecks.copy(status = statusOf(revoked))
        val report = ValidationReport.credential(checks, relaxedPolicy, evaluatedAt)
        report.namedChecks.filterNot { it.satisfied }.map { it.name } shouldBe listOf("status.mechanisms[0]")
        report.firstRejection().shouldBeInstanceOf<TokenStatusException>().status shouldBe TokenStatus.Invalid
    }

    "skipping the status only records it" {
        credentialChecks.namedUnder(strictPolicy.copy(status = StatusPolicy.Skip))
            .filter { it.name.startsWith("status.") }
            .all { it.requirement == OPTIONAL } shouldBe true
    }

    "the signer of a status list token is trusted as the status policy requires" {
        fun signerTrust(trust: TrustPolicy) = ValidationReport.statusListToken(passingToken, trust, evaluatedAt)
            .namedChecks.requirements().getValue("signerTrust")
        signerTrust(TrustPolicy.RequireAuthorizedSigner) shouldBe REQUIRED
        signerTrust(TrustPolicy.IntegrityOnly) shouldBe OPTIONAL
    }

    "an unsigned request object needs no trust" {
        val unsigned = RequestObjectChecks(
            parsing = Passed,
            signature = NotApplicable,
            trust = TrustValidation(NotApplicable),
            timeliness = NotApplicable,
            clientId = Passed,
            walletNonce = NotApplicable,
            expectedOrigin = NotApplicable,
        )
        fun RequestObjectChecks.trustRequirement() =
            ValidationReport.requestObject(this, strictPolicy, null, null, evaluatedAt)
                .namedChecks.requirements().getValue("trust")
        unsigned.trustRequirement() shouldBe REQUIRED_IF_APPLICABLE
        unsigned.copy(signature = Passed).trustRequirement() shouldBe REQUIRED
    }

    "presentation and response checks apply where defined" {
        val presentation = PresentationChecks(
            parsing = Passed,
            signature = Passed,
            proofTime = NotApplicable,
            challenge = Passed,
            audience = Passed,
            presentationBinding = Failed(failure),
        )
        val report = ValidationReport.presentation(
            presentation,
            listOf(ValidationReport.credential(credentialChecks, strictPolicy, evaluatedAt)),
            evaluatedAt,
        )
        report.namedChecks.requirements().getValue("parsing") shouldBe REQUIRED
        report.namedChecks.drop(1).all { it.requirement == REQUIRED_IF_APPLICABLE } shouldBe true
        report.namedChecks.filterNot { it.satisfied }.map { it.name } shouldBe listOf("presentationBinding")
        report.decision shouldBe REJECTED
    }

    "a report records the requirements it has been decided under" {
        val wrongKey = credentialChecks.copy(holderBinding = Failed(failure))

        val bound = ValidationReport.credential(
            wrongKey,
            strictPolicy.copy(holderBinding = HolderBindingPolicy.RequireExpectedKey),
            evaluatedAt,
        )
        bound.decision shouldBe REJECTED
        bound.namedChecks.single { it.name == "holderBinding" }.apply {
            requirement shouldBe REQUIRED
            satisfied shouldBe false
        }
        bound.firstRejection() shouldBe failure

        val unbound = ValidationReport.credential(wrongKey, strictPolicy, evaluatedAt)
        unbound.decision shouldBe ACCEPTED
        unbound.namedChecks.single { it.name == "holderBinding" }.satisfied shouldBe true
    }

    "a rejected child is the rejection of its parent if the parent's own checks pass" {
        val rejectedCredential = ValidationReport.credential(
            credentialChecks.copy(issuerSignature = Failed(failure)),
            strictPolicy,
            evaluatedAt,
        )
        val passingPresentation = PresentationChecks(Passed, Passed, Passed, Passed, Passed, Passed)

        ValidationReport.presentation(passingPresentation, listOf(rejectedCredential), evaluatedAt)
            .firstRejection() shouldBe failure
    }
}
