package at.asitplus.wallet.lib.validation

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.JsonObject
import kotlin.time.Duration.Companion.seconds

private val walletProvider = TrustValidation(Passed, source = "wallet providers")

private val noStatus = StatusValidation(NotApplicable, emptyList(), NotApplicable)

/** Status, trust and timeliness can be relaxed, everything else can not. */
private val relaxedPolicy = ValidationPolicy(
    trust = TrustPolicy.IntegrityOnly,
    status = StatusPolicy.Skip,
    timeLeeway = 300.seconds,
    requireTimeliness = false,
)

private val ifPresentPolicy = strictPolicy.copy(status = ifPresent)

private val passingKeyAttestation = KeyAttestationChecks(
    parsing = Passed,
    signature = Passed,
    trust = walletProvider,
    timeliness = Passed,
    status = validStatus,
    nonce = Passed,
)

private val passingJwtProof = JwtProofChecks(
    parsing = Passed,
    signature = Passed,
    proofTime = Passed,
    nonce = Passed,
    audience = Passed,
)

private val passingClientAttestation = ClientAttestationChecks(
    parsing = Passed,
    signature = Passed,
    trust = walletProvider,
    timeliness = Passed,
    status = validStatus,
    clientId = Passed,
    popSignature = Passed,
    popTime = Passed,
    audience = Passed,
    challenge = Passed,
)

private val relyingPartyTrust = TrustValidation(Passed, source = "x509_san_dns anchors")

private val passingRequestObject = RequestObjectChecks(
    parsing = Passed,
    signature = Passed,
    trust = relyingPartyTrust,
    timeliness = Passed,
    clientId = Passed,
    walletNonce = NotApplicable,
    expectedOrigin = NotApplicable,
)

private val passingVerifierAttestation = VerifierAttestationChecks(
    parsing = Passed,
    signature = Passed,
    trust = relyingPartyTrust,
    timeliness = Passed,
    clientId = Passed,
)

private val passingAccessCertificate = AccessCertificateChecks(
    parsing = Passed,
    signature = Passed,
    trust = relyingPartyTrust,
    timeliness = Passed,
    clientId = Passed,
)

private val passingRegistrationCertificate = RegistrationCertificateChecks(
    parsing = Passed,
    signature = Passed,
    trust = relyingPartyTrust,
    timeliness = Passed,
    status = validStatus,
    linkage = Passed,
    requestAuthorization = Passed,
)

private val passingIssuerMetadata = IssuerMetadataChecks(
    parsing = Passed,
    signature = Passed,
    trust = relyingPartyTrust,
    timeliness = Passed,
    subject = Passed,
)

private fun keyAttestation(
    checks: KeyAttestationChecks = passingKeyAttestation,
    policy: ValidationPolicy = strictPolicy,
) =
    ValidationReport.keyAttestation(checks, policy, evaluatedAt)

private fun accessCertificate(checks: AccessCertificateChecks = passingAccessCertificate) =
    ValidationReport.accessCertificate(checks, strictPolicy, evaluatedAt)

private fun registrationCertificate(checks: RegistrationCertificateChecks = passingRegistrationCertificate) =
    ValidationReport.registrationCertificate(checks, strictPolicy, evaluatedAt)

private fun relyingParty(registrationCertificates: List<ValidationReport> = listOf(registrationCertificate())) =
    ValidationReport.relyingParty(
        checks = RelyingPartyChecks(Passed),
        accessCertificate = accessCertificate(),
        registrationCertificates = registrationCertificates,
        evaluatedAt = evaluatedAt,
    )

private val passingPresentation = PresentationChecks(Passed, Passed, Passed, Passed, Passed, Passed)

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

val ArtifactValidationRulesTest by matrixSuite {

    "key attestation" - {
        "all checks passed" {
            keyAttestation().decision shouldBe ACCEPTED
        }

        "untrusted wallet provider, expired, or without status are accepted only if the policy relaxes them" {
            val relaxed = passingKeyAttestation.copy(
                trust = walletProvider.copy(outcome = Blocked()),
                timeliness = Failed(failure),
                status = StatusValidation(Failed(failure), emptyList(), NotApplicable),
            )
            keyAttestation(relaxed, strictPolicy).decision shouldBe REJECTED
            keyAttestation(relaxed, relaxedPolicy).decision shouldBe ACCEPTED
        }

        "an issuer without nonce endpoint makes the nonce not applicable" {
            keyAttestation(passingKeyAttestation.copy(nonce = NotApplicable)).decision shouldBe ACCEPTED
        }

        "a revoked key storage is rejected" {
            val revoked = mechanism(observed = TokenStatus.Invalid)
                .copy(outcome = Failed(TokenStatusException(TokenStatus.Invalid)))
            keyAttestation(passingKeyAttestation.copy(status = statusOf(revoked))).decision shouldBe REJECTED
        }

        listOf(
            "parsing" to passingKeyAttestation.copy(parsing = Failed(failure)),
            "signature" to passingKeyAttestation.copy(signature = Failed(failure)),
            "nonce" to passingKeyAttestation.copy(nonce = Failed(failure)),
        ).asData(nameFn = { (name, _) -> "rejected for $name even under a relaxed policy" }) test { (_, checks) ->
            keyAttestation(checks, relaxedPolicy).decision shouldBe REJECTED
        }
    }

    "JWT proof" - {
        "without key attestation" {
            ValidationReport.jwtProof(passingJwtProof, keyAttestation = null, evaluatedAt).decision shouldBe ACCEPTED
        }

        "with an accepted key attestation" {
            val report = ValidationReport.jwtProof(passingJwtProof, keyAttestation(), evaluatedAt)
            report.decision shouldBe ACCEPTED
            report.children shouldBe listOf(keyAttestation())
        }

        "a rejected key attestation rejects the proof" {
            val rejected = keyAttestation(passingKeyAttestation.copy(signature = Failed(failure)))
            ValidationReport.jwtProof(passingJwtProof, rejected, evaluatedAt).decision shouldBe REJECTED
        }

        listOf(
            "parsing" to passingJwtProof.copy(parsing = Failed(failure)),
            "signature" to passingJwtProof.copy(signature = Failed(failure)),
            "proof time" to passingJwtProof.copy(proofTime = Failed(failure)),
            "nonce" to passingJwtProof.copy(nonce = Blocked()),
            "audience" to passingJwtProof.copy(audience = Failed(failure)),
        ).asData(nameFn = { (name, _) -> "rejected for $name" }) test { (_, checks) ->
            ValidationReport.jwtProof(checks, keyAttestation = null, evaluatedAt).decision shouldBe REJECTED
        }

        "contains a key attestation report only" {
            shouldThrow<IllegalArgumentException> {
                ValidationReport.jwtProof(passingJwtProof, tokenReport(), evaluatedAt)
            }
        }
    }

    "client attestation" - {
        "all checks passed" {
            ValidationReport.clientAttestation(passingClientAttestation, strictPolicy, evaluatedAt)
                .decision shouldBe ACCEPTED
        }

        "an expired attestation is accepted only if the policy relaxes timeliness" {
            val expired = passingClientAttestation.copy(timeliness = Failed(failure))
            ValidationReport.clientAttestation(expired, strictPolicy, evaluatedAt).decision shouldBe REJECTED
            ValidationReport.clientAttestation(expired, relaxedPolicy, evaluatedAt).decision shouldBe ACCEPTED
        }

        listOf(
            "client identifier" to passingClientAttestation.copy(clientId = Failed(failure)),
            "proof of possession signature" to passingClientAttestation.copy(popSignature = Failed(failure)),
            "proof of possession time" to passingClientAttestation.copy(popTime = Failed(failure)),
            "audience" to passingClientAttestation.copy(audience = Failed(failure)),
            "challenge" to passingClientAttestation.copy(challenge = Blocked()),
        ).asData(nameFn = { (name, _) -> "rejected for $name even under a relaxed policy" }) test { (_, checks) ->
            ValidationReport.clientAttestation(checks, relaxedPolicy, evaluatedAt).decision shouldBe REJECTED
        }

        "without wallet provider anchors trust is blocked, which fails closed" {
            val noAnchors = passingClientAttestation.copy(trust = walletProvider.copy(outcome = Blocked()))
            ValidationReport.clientAttestation(noAnchors, strictPolicy, evaluatedAt).decision shouldBe REJECTED
        }
    }

    "request object" - {
        fun requestObject(
            checks: RequestObjectChecks = passingRequestObject,
            policy: ValidationPolicy = strictPolicy,
            verifierAttestation: ValidationReport? = null,
            relyingParty: ValidationReport? = null,
        ) = ValidationReport.requestObject(checks, policy, verifierAttestation, relyingParty, evaluatedAt)

        "a signed request with a trusted relying party" {
            requestObject().decision shouldBe ACCEPTED
        }

        "an unsigned request has no signer to trust" {
            requestObject(
                passingRequestObject.copy(
                    signature = NotApplicable,
                    trust = relyingPartyTrust.copy(outcome = NotApplicable),
                )
            ).decision shouldBe ACCEPTED
        }

        "a signed request has to have its trust evaluated" {
            requestObject(passingRequestObject.copy(trust = relyingPartyTrust.copy(outcome = NotApplicable)))
                .decision shouldBe REJECTED
        }

        "an untrusted relying party is accepted only under integrity only" {
            val untrusted = passingRequestObject.copy(trust = relyingPartyTrust.copy(outcome = Failed(failure)))
            requestObject(untrusted).decision shouldBe REJECTED
            requestObject(untrusted, relaxedPolicy).decision shouldBe ACCEPTED
        }

        "a mismatching client identifier or origin rejects" {
            requestObject(passingRequestObject.copy(clientId = Failed(failure)), relaxedPolicy)
                .decision shouldBe REJECTED
            requestObject(passingRequestObject.copy(expectedOrigin = Failed(failure)), relaxedPolicy)
                .decision shouldBe REJECTED
        }

        "a rejected verifier attestation or relying party rejects the request" {
            val rejectedAttestation = ValidationReport.verifierAttestation(
                passingVerifierAttestation.copy(clientId = Failed(failure)), strictPolicy, evaluatedAt
            )
            requestObject(verifierAttestation = rejectedAttestation).decision shouldBe REJECTED
            val rejectedRelyingParty = relyingParty(
                listOf(registrationCertificate(passingRegistrationCertificate.copy(linkage = Failed(failure))))
            )
            requestObject(relyingParty = rejectedRelyingParty).decision shouldBe REJECTED
        }

        "with accepted children" {
            val attestation =
                ValidationReport.verifierAttestation(passingVerifierAttestation, strictPolicy, evaluatedAt)
            val report = requestObject(verifierAttestation = attestation, relyingParty = relyingParty())
            report.decision shouldBe ACCEPTED
            report.children shouldBe listOf(attestation, relyingParty())
        }

        "contains the right kinds of reports only" {
            shouldThrow<IllegalArgumentException> { requestObject(verifierAttestation = relyingParty()) }
            shouldThrow<IllegalArgumentException> { requestObject(relyingParty = keyAttestation()) }
        }
    }

    "relying party" - {
        "access certificate and registration certificates accepted" {
            relyingParty().decision shouldBe ACCEPTED
        }

        "without registration certificates" {
            relyingParty(emptyList()).decision shouldBe ACCEPTED
        }

        "mdoc reader authentication has no client identifier to match" {
            accessCertificate(passingAccessCertificate.copy(clientId = NotApplicable)).decision shouldBe ACCEPTED
        }

        "a revoked registration certificate rejects the relying party" {
            val revoked = mechanism(observed = TokenStatus.Invalid)
                .copy(outcome = Failed(TokenStatusException(TokenStatus.Invalid)))
            val certificate = registrationCertificate(passingRegistrationCertificate.copy(status = statusOf(revoked)))
            certificate.decision shouldBe REJECTED
            relyingParty(listOf(registrationCertificate(), certificate)).decision shouldBe REJECTED
        }

        "a registration certificate without status claim under validate if present" {
            ValidationReport.registrationCertificate(
                passingRegistrationCertificate.copy(status = noStatus), ifPresentPolicy, evaluatedAt
            ).decision shouldBe ACCEPTED
        }

        "unregistered requested claims reject" {
            registrationCertificate(passingRegistrationCertificate.copy(requestAuthorization = Failed(failure)))
                .decision shouldBe REJECTED
        }

        "failed request data extraction rejects" {
            ValidationReport.relyingParty(
                RelyingPartyChecks(Failed(failure)), accessCertificate(), emptyList(), evaluatedAt
            ).decision shouldBe REJECTED
        }

        "contains certificate reports only" {
            shouldThrow<IllegalArgumentException> {
                ValidationReport.relyingParty(RelyingPartyChecks(Passed), keyAttestation(), emptyList(), evaluatedAt)
            }
            shouldThrow<IllegalArgumentException> {
                ValidationReport.relyingParty(
                    RelyingPartyChecks(Passed), accessCertificate(), listOf(accessCertificate()), evaluatedAt
                )
            }
        }
    }

    "issuer metadata" - {
        "all checks passed" {
            ValidationReport.issuerMetadata(passingIssuerMetadata, strictPolicy, evaluatedAt).decision shouldBe ACCEPTED
        }

        "metadata of another issuer rejects even under a relaxed policy" {
            val otherIssuer = passingIssuerMetadata.copy(subject = Failed(failure))
            ValidationReport.issuerMetadata(otherIssuer, relaxedPolicy, evaluatedAt).decision shouldBe REJECTED
        }

        "an untrusted signer is accepted only under integrity only" {
            val untrusted = passingIssuerMetadata.copy(trust = relyingPartyTrust.copy(outcome = Failed(failure)))
            ValidationReport.issuerMetadata(untrusted, strictPolicy, evaluatedAt).decision shouldBe REJECTED
            ValidationReport.issuerMetadata(untrusted, relaxedPolicy, evaluatedAt).decision shouldBe ACCEPTED
        }
    }

    "presentation validation result" - {
        val credential = ValidationReport.credential(
            checks = CredentialChecks(
                parsing = Passed,
                issuerSignature = Passed,
                issuerTrust = trusted,
                semantics = Passed,
                disclosedItems = emptyList(),
                holderBinding = NotApplicable,
                timeliness = TimelinessValidation(Passed, details = null),
                status = validStatus,
            ),
            policy = strictPolicy,
            holderBinding = HolderBindingPolicy.None,
            evaluatedAt = evaluatedAt,
        )
        val accepted = ValidationReport.presentation(passingPresentation, listOf(credential), evaluatedAt)
        val rejected = ValidationReport.presentation(
            passingPresentation.copy(audience = Failed(failure)), listOf(credential), evaluatedAt
        )
        val presentation = ValidatedPresentation.VcJwt(vcJwt)

        "an accepted report carries the presentation" {
            PresentationValidationResult(accepted, presentation).presentation shouldBe presentation
        }

        "a rejected report carries no presentation" {
            PresentationValidationResult(rejected, presentation = null).presentation.shouldBeNull()
            shouldThrow<IllegalArgumentException> { PresentationValidationResult(rejected, presentation) }
            shouldThrow<IllegalArgumentException> { PresentationValidationResult(accepted, presentation = null) }
        }

        "holds a presentation report only" {
            shouldThrow<IllegalArgumentException> { PresentationValidationResult(credential, presentation) }
        }
    }

    "timeliness exception keeps the validity period" {
        val exception = TimelinessException(
            "expired",
            evaluatedAt,
            notBefore = null,
            notAfter = evaluatedAt - 1.seconds
        )
        exception.evaluatedAt shouldBe evaluatedAt
        exception.notBefore.shouldBeNull()
        exception.notAfter shouldBe evaluatedAt - 1.seconds
    }
}
