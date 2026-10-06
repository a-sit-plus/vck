package at.asitplus.wallet.lib.validation

import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import kotlin.time.Instant

enum class ValidationDecision { ACCEPTED, REJECTED }

/**
 * The outcome of a single check.
 */
sealed interface CheckOutcome {
    /** The check ran and passed. */
    data object Passed : CheckOutcome

    /** The check ran and failed, with the error of the validator that found it. */
    data class Failed(val throwable: Throwable) : CheckOutcome

    /**
     * The check could not run, e.g. because a prerequisite failed, trust anchors are missing, or a status list is
     * unavailable. Never satisfies a required check.
     */
    data class Blocked(val cause: Throwable? = null) : CheckOutcome

    /** The check does not apply, e.g. because the policy does not ask for it or the credential has no such claim. */
    data object NotApplicable : CheckOutcome
}

/**
 * Identifies a disclosed item supplied with a credential, without carrying its value.
 */
sealed interface DisclosedItemReference {
    /** The disclosure at [disclosureIndex] in the order supplied, and the claim it discloses, once known. */
    data class SdJwt(
        val disclosureIndex: Int,
        val claimPath: String?
    ) : DisclosedItemReference

    data class Mdoc(
        val namespace: String,
        val elementIdentifier: String,
        val digestId: UInt,
    ) : DisclosedItemReference
}

/**
 * Checks of one supplied SD-JWT disclosure or mdoc issuer-signed item. A parsing failure blocks [digest] and
 * [structure] of this item only.
 */
data class DisclosedItemValidation(
    val reference: DisclosedItemReference,
    val parsing: CheckOutcome,
    /** Whether the item matches exactly one digest signed by the issuer. */
    val digest: CheckOutcome,
    /** Whether the item occupies a valid position, e.g. no duplicate or colliding claim. */
    val structure: CheckOutcome,
)

data class TimelinessValidation(
    val outcome: CheckOutcome,
    /** Details of the format-specific timeliness validators, if they could run. */
    val details: CredentialTimelinessValidationSummary?,
)

/**
 * Whether a signer is authorized by the trust anchors configured for the artifact.
 */
data class TrustValidation(
    val outcome: CheckOutcome,
    /**
     * For a credential and its status list tokens, the signed credential identifier the anchors were selected for,
     * if it could be determined. `null` for other artifacts, which are trusted per artifact kind.
     */
    val credentialIdentifier: String?,
    /** Names the trust source the anchors came from, e.g. the URL of a trust list, but never the certificates. */
    val source: String? = null,
)

/**
 * The checks of one status mechanism advertised by an artifact, i.e. a status list or an identifier list.
 */
data class StatusMechanismValidation(
    val reference: RevocationListInfo,
    /** The report of the status list token this mechanism references, see [StatusListTokenChecks]. */
    val token: ValidationReport,
    /** Passed if the token is accepted and the status it yields is accepted, see [statusMechanismValidation]. */
    val outcome: CheckOutcome,
    /** The verified status, also when the policy does not accept it. */
    val observed: TokenStatus?,
) {
    init {
        require(token.checks is StatusListTokenChecks) { "Token has to be a status list token report" }
    }
}

data class StatusValidation(
    /** Whether the artifact advertises a status, as far as the policy requires one. */
    val claim: CheckOutcome,
    /** One entry per advertised mechanism, only if [claim] passed. */
    val mechanisms: List<StatusMechanismValidation>,
    /** Whether all mechanisms yield the same status, see [statusAgreement]. */
    val agreement: CheckOutcome,
) {
    init {
        require(claim == CheckOutcome.Passed || mechanisms.isEmpty()) {
            "Status mechanisms are only evaluated for a status claim that passed"
        }
    }
}

/**
 * The checks of one node of a [ValidationReport].
 */
sealed interface ValidationChecks

/**
 * The checks of a single credential, independent of how it was presented.
 */
data class CredentialChecks(
    val parsing: CheckOutcome,
    /** Cryptographic integrity of the issuer signature, not whether the issuer is trusted. */
    val issuerSignature: CheckOutcome,
    val issuerTrust: TrustValidation,
    val semantics: CheckOutcome,
    /** One entry per supplied disclosure or issuer-signed item, in the order supplied. */
    val disclosedItems: List<DisclosedItemValidation>,
    val holderBinding: CheckOutcome,
    val timeliness: TimelinessValidation,
    val status: StatusValidation,
) : ValidationChecks

/**
 * The checks of a status list token (JWT or CWT) that a status mechanism references.
 */
data class StatusListTokenChecks(
    /** Whether the token could be retrieved, e.g. a status list token resolver is configured and succeeded. */
    val retrieval: CheckOutcome,
    /** Media type, decoding, list kind matching the reference, and the index or identifier can be looked up. */
    val parsing: CheckOutcome,
    val signature: CheckOutcome,
    /** Whether the signer is issued by a status anchor for the referencing artifact, never directly trusted. */
    val signerTrust: TrustValidation,
    /** Whether `sub` equals the URI of the reference. */
    val subject: CheckOutcome,
    /** `exp`, and the time of resolution plus `ttl`. Always required: an expired list never determines a status. */
    val timeliness: CheckOutcome,
) : ValidationChecks

/**
 * The checks of one presentation, i.e. what binds its credentials to the holder and the request:
 * The [ValidationReport] holding these has the reports of the presented credentials as its children.
 *
 * A check is [CheckOutcome.NotApplicable] only where the format does not define it, e.g. [presentationBinding] for
 * an mdoc, or where the request does not require a holder proof, see [ValidationReport.presentation].
 */
data class PresentationChecks(
    /** Media type and claims of the holder proof, e.g. a key binding JWT, a VP-JWT, or the mdoc `DeviceSigned`. */
    val parsing: CheckOutcome,
    /**
     * The holder's signature: the key binding JWT with the credential's `cnf` key, the signed VP of VC-JWTs, or the
     * mdoc device authentication over the transport-specific session transcript.
     */
    val signature: CheckOutcome,
    /** Time claims of the holder proof, e.g. key binding JWT `iat` or VP-JWT `exp`. Never relaxed by the policy. */
    val proofTime: CheckOutcome,
    val challenge: CheckOutcome,
    val audience: CheckOutcome,
    /** What else binds the proof to this presentation, i.e. the SD-JWT `sd_hash` and transaction data hashes. */
    val presentationBinding: CheckOutcome,
) : ValidationChecks

/**
 * The checks of a complete protocol response, e.g. an OpenID4VP authorization response or an ISO/IEC 18013-7
 * Annex C device response: The [ValidationReport] holding these has the reports of the presentations as children.
 *
 * A check is [CheckOutcome.NotApplicable] only where the protocol or transport does not define it, e.g.
 * [expectedOrigin] outside of the Digital Credentials API, see [ValidationReport.protocolResponse].
 */
data class ProtocolResponseChecks(
    val parsing: CheckOutcome,
    val encryption: CheckOutcome,
    val expectedOrigin: CheckOutcome,
    /** Whether the response answers a request this party sent and has not been answered before. */
    val requestState: CheckOutcome,
    /**
     * Whether the accepted presentations satisfy the request, e.g. DCQL credential sets or ISO document requests.
     * Rejected presentations do not count towards this.
     */
    val submissionRequirements: CheckOutcome,
) : ValidationChecks

/**
 * The result of a validation, as a tree: a credential report is a leaf (its status list tokens are reported in its
 * status mechanisms), a presentation report contains the reports of its credentials, and a protocol response report
 * contains the reports of its presentations. Other artifacts nest the same way, e.g. a JWT proof contains its key
 * attestation.
 *
 * The [decision] is always derived from [checks] and [children], so a report can only be created through the
 * factories in the companion, one per kind of [ValidationChecks]: [CheckOutcome.Blocked] never satisfies a required
 * check, and [CheckOutcome.NotApplicable] only one the policy makes optional or the artifact does not define.
 * A report describes a validation at [evaluatedAt] under a particular policy: it is not a durable proof that a status
 * or trust decision remains valid.
 */
@ConsistentCopyVisibility
data class ValidationReport private constructor(
    val checks: ValidationChecks,
    val children: List<ValidationReport>,
    val decision: ValidationDecision,
    val evaluatedAt: Instant,
) {
    companion object {
        /** Report of a single credential, accepted if every check [policy] and [holderBinding] require passed. */
        fun credential(
            checks: CredentialChecks,
            policy: ValidationPolicy,
            holderBinding: HolderBindingPolicy,
            evaluatedAt: Instant,
        ) = leaf(checks, checks.meets(policy, holderBinding), evaluatedAt)

        /**
         * Report of a status list token, accepted if every check passed, and its signer is authorized as [signerTrust]
         * requires, i.e. the `signerTrust` of the [StatusPolicy] of the artifact referencing it.
         */
        fun statusListToken(
            checks: StatusListTokenChecks,
            signerTrust: TrustPolicy,
            evaluatedAt: Instant,
        ) = leaf(checks, checks.meets(signerTrust), evaluatedAt)

        /**
         * Report of a presentation of one or more [credentials], accepted if no check of [checks] failed or was
         * blocked, and every credential is accepted.
         */
        fun presentation(
            checks: PresentationChecks,
            credentials: List<ValidationReport>,
            evaluatedAt: Instant,
        ): ValidationReport {
            require(credentials.isNotEmpty()) { "A presentation contains at least one credential" }
            credentials.requireChecks<CredentialChecks>()
            return parent(checks, credentials, checks.satisfied(), evaluatedAt)
        }

        /**
         * Report of a protocol response with its [presentations], accepted if no check of [checks] failed or was
         * blocked. A rejected presentation does not reject the response by itself: it is kept as a child, and
         * [ProtocolResponseChecks.submissionRequirements] has to be evaluated over the accepted presentations only,
         * so the response is rejected only if the request can not be satisfied without the rejected ones.
         */
        fun protocolResponse(
            checks: ProtocolResponseChecks,
            presentations: List<ValidationReport>,
            evaluatedAt: Instant,
        ): ValidationReport {
            presentations.requireChecks<PresentationChecks>()
            // Rejected presentations are kept, but only the accepted ones count, through submissionRequirements.
            return ValidationReport(checks, presentations, checks.satisfied().toDecision(), evaluatedAt)
        }

        /**
         * Report of an OpenID4VCI JWT proof, accepted if every check passed, and its embedded [keyAttestation], if
         * any, is accepted.
         */
        fun jwtProof(
            checks: JwtProofChecks,
            keyAttestation: ValidationReport?,
            evaluatedAt: Instant,
        ): ValidationReport {
            val children = listOfNotNull(keyAttestation).requireChecks<KeyAttestationChecks>()
            return parent(checks, children, checks.satisfied(), evaluatedAt)
        }

        /** Report of a key attestation, standalone as `attestation` proof, or embedded in a JWT proof. */
        fun keyAttestation(
            checks: KeyAttestationChecks,
            policy: ValidationPolicy,
            evaluatedAt: Instant,
        ) = leaf(checks, checks.meets(policy), evaluatedAt)

        /** Report of a client (wallet instance) attestation together with its proof of possession. */
        fun clientAttestation(
            checks: ClientAttestationChecks,
            policy: ValidationPolicy,
            evaluatedAt: Instant,
        ) = leaf(checks, checks.meets(policy), evaluatedAt)

        /**
         * Report of an OpenID4VP request object, accepted if every check [policy] requires passed, and its
         * [verifierAttestation] and [relyingParty] reports, if any, are accepted.
         */
        fun requestObject(
            checks: RequestObjectChecks,
            policy: ValidationPolicy,
            verifierAttestation: ValidationReport?,
            relyingParty: ValidationReport?,
            evaluatedAt: Instant,
        ): ValidationReport {
            listOfNotNull(verifierAttestation).requireChecks<VerifierAttestationChecks>()
            listOfNotNull(relyingParty).requireChecks<RelyingPartyChecks>()
            val children = listOfNotNull(verifierAttestation, relyingParty)
            return parent(checks, children, checks.meets(policy), evaluatedAt)
        }

        /** Report of a verifier attestation, i.e. the `verifier_attestation` client identifier prefix. */
        fun verifierAttestation(
            checks: VerifierAttestationChecks,
            policy: ValidationPolicy,
            evaluatedAt: Instant,
        ) = leaf(checks, checks.meets(policy), evaluatedAt)

        /**
         * Report of a wallet-relying party, accepted if its request data could be extracted, its [accessCertificate]
         * is accepted, and every one of its [registrationCertificates] is accepted.
         */
        fun relyingParty(
            checks: RelyingPartyChecks,
            accessCertificate: ValidationReport,
            registrationCertificates: List<ValidationReport>,
            evaluatedAt: Instant,
        ): ValidationReport {
            listOf(accessCertificate).requireChecks<AccessCertificateChecks>()
            registrationCertificates.requireChecks<RegistrationCertificateChecks>()
            val children = listOf(accessCertificate) + registrationCertificates
            return parent(checks, children, checks.satisfied(), evaluatedAt)
        }

        /** Report of a wallet-relying party access certificate (WRPAC). */
        fun accessCertificate(
            checks: AccessCertificateChecks,
            policy: ValidationPolicy,
            evaluatedAt: Instant,
        ) = leaf(checks, checks.meets(policy), evaluatedAt)

        /** Report of a wallet-relying party registration certificate (WRPRC). */
        fun registrationCertificate(
            checks: RegistrationCertificateChecks,
            policy: ValidationPolicy,
            evaluatedAt: Instant,
        ) = leaf(checks, checks.meets(policy), evaluatedAt)

        /** Report of signed credential issuer metadata, as received by a wallet. */
        fun issuerMetadata(
            checks: IssuerMetadataChecks,
            policy: ValidationPolicy,
            evaluatedAt: Instant,
        ) = leaf(checks, checks.meets(policy), evaluatedAt)

        private fun leaf(checks: ValidationChecks, accepted: Boolean, evaluatedAt: Instant) =
            ValidationReport(checks, emptyList(), accepted.toDecision(), evaluatedAt)

        /** A parent is accepted if its own checks are, and every child is accepted. */
        private fun parent(
            checks: ValidationChecks,
            children: List<ValidationReport>,
            accepted: Boolean,
            evaluatedAt: Instant,
        ) = ValidationReport(checks, children, (accepted && children.allAccepted()).toDecision(), evaluatedAt)

        private inline fun <reified T : ValidationChecks> List<ValidationReport>.requireChecks() = also {
            require(all { it.checks is T }) { "Children have to be reports of ${T::class.simpleName}" }
        }

        private fun List<ValidationReport>.allAccepted() = all { it.decision == ValidationDecision.ACCEPTED }

        private fun Boolean.toDecision() = if (this) ValidationDecision.ACCEPTED else ValidationDecision.REJECTED
    }
}
