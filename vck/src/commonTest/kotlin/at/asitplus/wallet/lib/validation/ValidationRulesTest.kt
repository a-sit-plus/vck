package at.asitplus.wallet.lib.validation

import at.asitplus.KmmResult
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonObject
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private val passingChecks = CredentialChecks(
    parsing = Passed,
    issuerSignature = Passed,
    issuerTrust = trusted,
    semantics = Passed,
    disclosedItems = listOf(
        DisclosedItemValidation(DisclosedItemReference.SdJwt(0, "given_name"), Passed, Passed, Passed)
    ),
    holderBinding = Passed,
    timeliness = TimelinessValidation(Passed, details = null),
    status = validStatus,
)

private fun CredentialChecks.decisionUnder(
    policy: ValidationPolicy = strictPolicy,
    holderBinding: HolderBindingPolicy = HolderBindingPolicy.RequireExpectedKey,
) = ValidationReport.credential(this, policy, holderBinding, evaluatedAt).decision

private val passingPresentation = PresentationChecks(
    parsing = Passed,
    signature = Passed,
    proofTime = Passed,
    challenge = Passed,
    audience = Passed,
    presentationBinding = Passed,
)

private val passingResponse = ProtocolResponseChecks(
    parsing = Passed,
    encryption = Passed,
    expectedOrigin = NotApplicable,
    requestState = Passed,
    submissionRequirements = Passed,
)

private fun credentialReport(checks: CredentialChecks) =
    ValidationReport.credential(checks, strictPolicy, HolderBindingPolicy.RequireExpectedKey, evaluatedAt)

private val acceptedCredentialReport = credentialReport(passingChecks)

private val rejectedCredentialReport = credentialReport(passingChecks.copy(semantics = Failed(failure)))

private val vcJwt = ValidatedCredential.VcJwt(
    VerifiableCredentialJws(
        vc = VerifiableCredential(
            id = "urn:uuid:1",
            issuer = "https://issuer.example.com",
            issuanceDate = evaluatedAt,
            expirationDate = null,
            credentialStatus = null,
            credentialSubject = JsonObject(emptyMap()),
            credentialType = "ExampleCredential",
        ),
        subject = null,
        notBefore = evaluatedAt,
        issuer = "https://issuer.example.com",
        expiration = null,
        jwtId = "urn:uuid:1",
    )
)

val ValidationRulesTest by matrixSuite {

    "credential decision" - {
        "all required checks passed" {
            passingChecks.decisionUnder() shouldBe ACCEPTED
        }

        "a parsing failure blocks every dependent check" {
            val parsingFailure = IllegalArgumentException("not a JWS")
            val checks = credentialChecksWithoutPrerequisites(Failed(parsingFailure), issuerSignature = Passed)

            checks.parsing shouldBe Failed(parsingFailure)
            checks.issuerSignature.shouldBeInstanceOf<Blocked>()
            checks.issuerTrust.outcome.shouldBeInstanceOf<Blocked>()
            checks.semantics.shouldBeInstanceOf<Blocked>()
            checks.holderBinding.shouldBeInstanceOf<Blocked>()
            checks.timeliness.outcome.shouldBeInstanceOf<Blocked>()
            checks.status.claim.shouldBeInstanceOf<Blocked>()
            checks.disclosedItems.shouldBeEmpty()
            checks.decisionUnder() shouldBe REJECTED
        }

        "a signature failure is kept and blocks every check depending on claims" {
            val signatureFailure = IllegalStateException("signature invalid")
            val checks = credentialChecksWithoutPrerequisites(Passed, Failed(signatureFailure))

            checks.parsing shouldBe Passed
            checks.issuerSignature shouldBe Failed(signatureFailure)
            checks.issuerTrust.outcome.shouldBeInstanceOf<Blocked>()
            checks.issuerTrust.credentialIdentifier.shouldBeNull()
            checks.decisionUnder() shouldBe REJECTED
        }

        "prerequisites that passed are not reported as missing" {
            shouldThrow<IllegalArgumentException> { credentialChecksWithoutPrerequisites(Passed, Passed) }
        }

        "a dependent check is not evaluated after its prerequisite did not pass" {
            var evaluated = false
            Failed(failure).ifPassed { evaluated = true; Passed }.shouldBeInstanceOf<Blocked>()
            evaluated shouldBe false
            Passed.ifPassed { Failed(failure) } shouldBe Failed(failure)
        }

        "issuer trust" - {
            listOf(
                "blocked under required trust" to Triple(Blocked(), TrustPolicy.RequireAuthorizedSigner, REJECTED),
                "failed under required trust" to Triple(Failed(failure), TrustPolicy.RequireAuthorizedSigner, REJECTED),
                "not applicable under required trust" to
                        Triple(NotApplicable, TrustPolicy.RequireAuthorizedSigner, REJECTED),
                "not applicable under integrity only" to Triple(NotApplicable, TrustPolicy.IntegrityOnly, ACCEPTED),
            ).asData(nameFn = { (name, _) -> name }) test { (_, case) ->
                val (outcome, trust, expected) = case
                passingChecks.copy(issuerTrust = TrustValidation(outcome, "urn:eudi:pid:1", source = null))
                    .decisionUnder(strictPolicy.copy(trust = trust)) shouldBe expected
            }
        }

        "an invalid supplied item rejects the credential" {
            val invalidItem =
                DisclosedItemValidation(DisclosedItemReference.SdJwt(1, null), Passed, Failed(failure), Passed)
            passingChecks.copy(disclosedItems = passingChecks.disclosedItems + invalidItem)
                .decisionUnder() shouldBe REJECTED
        }

        "an unparseable supplied item rejects the credential" {
            val item = DisclosedItemValidation(
                reference = DisclosedItemReference.Mdoc("org.iso.18013.5.1", "family_name", 3U),
                parsing = Failed(failure),
                digest = Blocked(),
                structure = Blocked(),
            )
            passingChecks.copy(disclosedItems = listOf(item)).decisionUnder() shouldBe REJECTED
        }

        "withheld claims, i.e. no supplied items, are accepted" {
            passingChecks.copy(disclosedItems = emptyList()).decisionUnder() shouldBe ACCEPTED
        }

        "holder binding" - {
            listOf(
                "missing expected key is blocked" to
                        Triple(Blocked(), HolderBindingPolicy.RequireExpectedKey, REJECTED),
                "wrong key" to Triple(Failed(failure), HolderBindingPolicy.RequireExpectedKey, REJECTED),
                "not required" to Triple(NotApplicable, HolderBindingPolicy.None, ACCEPTED),
            ).asData(nameFn = { (name, _) -> name }) test { (_, case) ->
                val (outcome, holderBinding, expected) = case
                passingChecks.copy(holderBinding = outcome)
                    .decisionUnder(holderBinding = holderBinding) shouldBe expected
            }
        }

        "timeliness" - {
            listOf(
                "expired credential under required timeliness" to Triple(Failed(failure), true, REJECTED),
                "missing time evidence under required timeliness" to Triple(Blocked(), true, REJECTED),
                "expired credential when timeliness is not required" to Triple(Failed(failure), false, ACCEPTED),
            ).asData(nameFn = { (name, _) -> name }) test { (_, case) ->
                val (outcome, requireTimeliness, expected) = case
                val checks = passingChecks.copy(timeliness = TimelinessValidation(outcome, details = null))
                val report = ValidationReport.credential(
                    checks = checks,
                    policy = strictPolicy.copy(requireTimeliness = requireTimeliness),
                    holderBinding = HolderBindingPolicy.RequireExpectedKey,
                    evaluatedAt = evaluatedAt,
                )
                report.decision shouldBe expected
                (report.checks as CredentialChecks).timeliness.outcome shouldBe outcome
            }
        }
    }

    "status" - {
        "no status claim" - {
            listOf(
                "skip" to Triple(StatusPolicy.Skip as StatusPolicy, NotApplicable as CheckOutcome, ACCEPTED),
                "validate if present" to Triple(ifPresent, NotApplicable, ACCEPTED),
                "require claim" to Triple(requireClaim, Failed(failure), REJECTED),
            ).asData(nameFn = { (name, _) -> name }) test { (_, case) ->
                val (policy, expectedClaim, expectedDecision) = case
                val claim = statusClaimOutcome(policy, claimPresent = false)
                when (expectedClaim) {
                    is Failed -> claim.shouldBeInstanceOf<Failed>()
                    else -> claim shouldBe expectedClaim
                }
                passingChecks.copy(status = StatusValidation(claim, emptyList(), statusAgreement(emptyList())))
                    .decisionUnder(strictPolicy.copy(status = policy)) shouldBe expectedDecision
            }
        }

        "a present claim is checked unless skipped" {
            statusClaimOutcome(StatusPolicy.Skip, claimPresent = true) shouldBe NotApplicable
            statusClaimOutcome(ifPresent, claimPresent = true) shouldBe Passed
            statusClaimOutcome(requireClaim, claimPresent = true) shouldBe Passed
        }

        "a claim without mechanisms is not a valid status" {
            passingChecks.copy(status = StatusValidation(Passed, emptyList(), statusAgreement(emptyList())))
                .decisionUnder() shouldBe REJECTED
        }

        "mechanisms are only listed for a claim that passed" {
            shouldThrow<IllegalArgumentException> {
                StatusValidation(NotApplicable, listOf(mechanism()), Passed)
            }
        }

        "mechanism" - {
            "valid status" {
                val mechanism =
                    statusMechanismValidation(
                        statusListInfo, tokenReport(), KmmResult.success(TokenStatus.Valid), requireClaim
                    )
                mechanism.outcome shouldBe Passed
                mechanism.observed shouldBe TokenStatus.Valid
            }

            "revoked status fails with the status, and is kept as observed" {
                val mechanism = statusMechanismValidation(
                    statusListInfo, tokenReport(), KmmResult.success(TokenStatus.Invalid), requireClaim
                )
                mechanism.outcome.shouldBeInstanceOf<Failed>()
                    .throwable.shouldBeInstanceOf<TokenStatusException>().status shouldBe TokenStatus.Invalid
                mechanism.observed shouldBe TokenStatus.Invalid
                passingChecks.copy(status = statusOf(mechanism)).decisionUnder() shouldBe REJECTED
            }

            "a status accepted by policy passes and is kept as observed" {
                val policy = StatusPolicy.RequireClaim(
                    signerTrust = TrustPolicy.RequireAuthorizedSigner,
                    accepted = setOf(TokenStatus.Valid, TokenStatus.Suspended),
                )
                val mechanism = statusMechanismValidation(
                    statusListInfo, tokenReport(), KmmResult.success(TokenStatus.Suspended), policy
                )
                mechanism.outcome shouldBe Passed
                mechanism.observed shouldBe TokenStatus.Suspended
                passingChecks.copy(status = statusOf(mechanism))
                    .decisionUnder(strictPolicy.copy(status = policy)) shouldBe ACCEPTED
            }

            "an unavailable status list blocks with the cause of its token report" {
                val unavailable = IllegalStateException("status list unavailable")
                val token = tokenReport(passingToken.copy(retrieval = Blocked(unavailable)))
                token.decision shouldBe REJECTED
                val mechanism =
                    statusMechanismValidation(statusListInfo, token, KmmResult.failure(unavailable), requireClaim)
                mechanism.outcome shouldBe Blocked(unavailable)
                mechanism.observed.shouldBeNull()
                mechanism.token shouldBe token
            }

            "a status that can not be looked up in an accepted token blocks with the lookup error" {
                val outOfBounds = IndexOutOfBoundsException("index out of bounds")
                val mechanism =
                    statusMechanismValidation(
                        statusListInfo, tokenReport(), KmmResult.failure(outOfBounds), requireClaim
                    )
                mechanism.outcome shouldBe Blocked(outOfBounds)
                mechanism.observed.shouldBeNull()
            }

            "an unauthorized status list signer blocks, and its status is not observed" {
                val unauthorized = IllegalArgumentException("No valid trust anchor could verify certificate")
                val token = tokenReport(
                    passingToken.copy(signerTrust = TrustValidation(Failed(unauthorized), "urn:eudi:pid:1", "PID"))
                )
                val mechanism =
                    statusMechanismValidation(statusListInfo, token, KmmResult.success(TokenStatus.Valid), requireClaim)
                mechanism.outcome shouldBe Blocked(unauthorized)
                mechanism.observed.shouldBeNull()
            }

            "signer trust is not required under integrity only" {
                val policy = StatusPolicy.RequireClaim(TrustPolicy.IntegrityOnly)
                val token = tokenReport(
                    checks = passingToken.copy(signerTrust = TrustValidation(NotApplicable, "urn:eudi:pid:1", null)),
                    signerTrust = TrustPolicy.IntegrityOnly,
                )
                val mechanism =
                    statusMechanismValidation(statusListInfo, token, KmmResult.success(TokenStatus.Valid), policy)
                mechanism.outcome shouldBe Passed
                passingChecks.copy(status = statusOf(mechanism))
                    .decisionUnder(strictPolicy.copy(status = policy)) shouldBe ACCEPTED
            }

            "a token report evaluated under another signer trust policy is a programming error" {
                val token = tokenReport(
                    checks = passingToken.copy(signerTrust = TrustValidation(NotApplicable, "urn:eudi:pid:1", null)),
                    signerTrust = TrustPolicy.IntegrityOnly,
                )
                shouldThrow<IllegalArgumentException> {
                    statusMechanismValidation(statusListInfo, token, KmmResult.success(TokenStatus.Valid), requireClaim)
                }
            }

            "status mechanisms are not validated when skipping status" {
                shouldThrow<IllegalArgumentException> {
                    statusMechanismValidation(
                        statusListInfo, tokenReport(), KmmResult.success(TokenStatus.Valid), StatusPolicy.Skip
                    )
                }
            }

            "references a status list token report only" {
                shouldThrow<IllegalArgumentException> {
                    StatusMechanismValidation(statusListInfo, acceptedCredentialReport, Passed, TokenStatus.Valid)
                }
            }
        }

        "status list token" - {
            "an expired token is rejected whatever the timeliness of the referencing artifact" {
                tokenReport(passingToken.copy(timeliness = Failed(failure))).decision shouldBe REJECTED
                tokenReport(
                    checks = passingToken.copy(
                        timeliness = Failed(failure),
                        signerTrust = TrustValidation(NotApplicable, null, null),
                    ),
                    signerTrust = TrustPolicy.IntegrityOnly,
                ).decision shouldBe REJECTED
            }

            listOf(
                "retrieval" to passingToken.copy(retrieval = Blocked()),
                "parsing" to passingToken.copy(parsing = Failed(failure)),
                "signature" to passingToken.copy(signature = Failed(failure)),
                "subject" to passingToken.copy(subject = Failed(failure)),
                "blocked signer trust" to passingToken.copy(signerTrust = TrustValidation(Blocked(), null, null)),
            ).asData(nameFn = { (name, _) -> "rejected for $name" }) test { (_, checks) ->
                tokenReport(checks).decision shouldBe REJECTED
            }
        }

        "agreement of several mechanisms" - {
            fun mechanism(observed: TokenStatus?) = mechanism(identifierListInfo, observed)

            "agreeing mechanisms pass" {
                val mechanisms = listOf(mechanism(), mechanism(TokenStatus.Valid))
                statusAgreement(mechanisms) shouldBe Passed
                passingChecks.copy(status = StatusValidation(Passed, mechanisms, statusAgreement(mechanisms)))
                    .decisionUnder() shouldBe ACCEPTED
            }

            "conflicting mechanisms fail" {
                val mechanisms = listOf(mechanism(), mechanism(TokenStatus.Suspended))
                statusAgreement(mechanisms).shouldBeInstanceOf<Failed>()
                passingChecks.copy(status = StatusValidation(Passed, mechanisms, statusAgreement(mechanisms)))
                    .decisionUnder() shouldBe REJECTED
            }

            "an unavailable mechanism blocks agreement" {
                val mechanisms = listOf(mechanism(), mechanism(null))
                statusAgreement(mechanisms).shouldBeInstanceOf<Blocked>()
                passingChecks.copy(status = StatusValidation(Passed, mechanisms, statusAgreement(mechanisms)))
                    .decisionUnder() shouldBe REJECTED
            }

            "a conflict dominates an unavailable mechanism" {
                statusAgreement(listOf(mechanism(), mechanism(TokenStatus.Invalid), mechanism(null)))
                    .shouldBeInstanceOf<Failed>()
            }

            "no mechanisms have nothing to agree on" {
                statusAgreement(emptyList()) shouldBe NotApplicable
            }
        }
    }

    "policy" - {
        "rejects a negative time leeway" {
            shouldThrow<IllegalArgumentException> { strictPolicy.copy(timeLeeway = (-1).seconds) }
        }

        "rejects an empty set of accepted token statuses" {
            shouldThrow<IllegalArgumentException> {
                StatusPolicy.ValidateIfPresent(TrustPolicy.RequireAuthorizedSigner, accepted = emptySet())
            }
            shouldThrow<IllegalArgumentException> {
                StatusPolicy.RequireClaim(TrustPolicy.RequireAuthorizedSigner, accepted = emptySet())
            }
        }
    }

    "presentation decision" - {
        "all applicable checks passed and every credential accepted" {
            ValidationReport.presentation(passingPresentation, listOf(acceptedCredentialReport), evaluatedAt)
                .decision shouldBe ACCEPTED
        }

        "a failed check rejects, and keeps the credential reports" {
            val report = ValidationReport.presentation(
                checks = passingPresentation.copy(challenge = Failed(failure)),
                credentials = listOf(acceptedCredentialReport),
                evaluatedAt = evaluatedAt,
            )
            report.decision shouldBe REJECTED
            report.children shouldBe listOf(acceptedCredentialReport)
        }

        "a blocked check rejects" {
            ValidationReport.presentation(
                checks = passingPresentation.copy(signature = Blocked()),
                credentials = listOf(acceptedCredentialReport),
                evaluatedAt = evaluatedAt,
            ).decision shouldBe REJECTED
        }

        "a failed proof time rejects, as there is no policy to relax it" {
            ValidationReport.presentation(
                checks = passingPresentation.copy(proofTime = Failed(failure)),
                credentials = listOf(acceptedCredentialReport),
                evaluatedAt = evaluatedAt,
            ).decision shouldBe REJECTED
        }

        "checks the format does not define are not applicable, e.g. sd_hash for an mdoc" {
            ValidationReport.presentation(
                checks = passingPresentation.copy(presentationBinding = NotApplicable),
                credentials = listOf(acceptedCredentialReport),
                evaluatedAt = evaluatedAt,
            ).decision shouldBe ACCEPTED
        }

        "a rejected credential rejects the presentation" {
            ValidationReport.presentation(
                checks = passingPresentation,
                credentials = listOf(acceptedCredentialReport, rejectedCredentialReport),
                evaluatedAt = evaluatedAt,
            ).decision shouldBe REJECTED
        }

        "contains at least one credential report" {
            shouldThrow<IllegalArgumentException> {
                ValidationReport.presentation(passingPresentation, emptyList(), evaluatedAt)
            }
            val presentation =
                ValidationReport.presentation(passingPresentation, listOf(acceptedCredentialReport), evaluatedAt)
            shouldThrow<IllegalArgumentException> {
                ValidationReport.presentation(passingPresentation, listOf(presentation), evaluatedAt)
            }
        }
    }

    "protocol response decision" - {
        val acceptedPresentation =
            ValidationReport.presentation(passingPresentation, listOf(acceptedCredentialReport), evaluatedAt)
        val rejectedPresentation =
            ValidationReport.presentation(passingPresentation, listOf(rejectedCredentialReport), evaluatedAt)

        "all applicable checks passed and every presentation accepted" {
            ValidationReport.protocolResponse(passingResponse, listOf(acceptedPresentation), evaluatedAt)
                .decision shouldBe ACCEPTED
        }

        "a rejected presentation does not reject the response, and keeps every report" {
            val report = ValidationReport.protocolResponse(
                checks = passingResponse,
                presentations = listOf(acceptedPresentation, rejectedPresentation),
                evaluatedAt = evaluatedAt,
            )
            report.decision shouldBe ACCEPTED
            report.children shouldBe listOf(acceptedPresentation, rejectedPresentation)
            report.children.map { it.decision } shouldBe listOf(ACCEPTED, REJECTED)
        }

        "a request that the accepted presentations do not satisfy rejects the response, and keeps every report" {
            val report = ValidationReport.protocolResponse(
                checks = passingResponse.copy(submissionRequirements = Failed(failure)),
                presentations = listOf(acceptedPresentation, rejectedPresentation),
                evaluatedAt = evaluatedAt,
            )
            report.decision shouldBe REJECTED
            report.children shouldBe listOf(acceptedPresentation, rejectedPresentation)
        }

        "contains presentation reports only" {
            shouldThrow<IllegalArgumentException> {
                ValidationReport.protocolResponse(passingResponse, listOf(acceptedCredentialReport), evaluatedAt)
            }
        }
    }

    "credential validation result" - {
        "an accepted report carries the credential" {
            CredentialValidationResult(acceptedCredentialReport, vcJwt).credential shouldBe vcJwt
        }

        "a rejected report carries no credential" {
            CredentialValidationResult(rejectedCredentialReport, credential = null).credential.shouldBeNull()
            shouldThrow<IllegalArgumentException> { CredentialValidationResult(rejectedCredentialReport, vcJwt) }
        }

        "an accepted report has to carry the credential" {
            shouldThrow<IllegalArgumentException> { CredentialValidationResult(acceptedCredentialReport, null) }
        }

        "holds a credential report only" {
            val presentation =
                ValidationReport.presentation(passingPresentation, listOf(acceptedCredentialReport), evaluatedAt)
            shouldThrow<IllegalArgumentException> { CredentialValidationResult(presentation, vcJwt) }
        }
    }

    "encoded mdoc input compares by content" {
        CredentialValidationInput.IsoMdoc(byteArrayOf(1, 2, 3)) shouldBe
                CredentialValidationInput.IsoMdoc(byteArrayOf(1, 2, 3))
        CredentialValidationInput.IsoMdoc(byteArrayOf(1, 2, 3)).toString() shouldBe "IsoMdoc(issuerSignedCbor=3 bytes)"
    }
}
