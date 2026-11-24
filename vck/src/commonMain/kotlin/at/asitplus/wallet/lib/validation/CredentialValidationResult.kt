package at.asitplus.wallet.lib.validation

import at.asitplus.iso.IssuerSigned
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.agent.SdJwtDecoded
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.jws.SdJwtSigned
import kotlinx.serialization.json.JsonObject
import kotlin.jvm.JvmOverloads

/**
 * A credential that passed every check its validation policy requires.
 */
sealed interface ValidatedCredential {
    data class VcJwt(
        /**
         * The VC-JWT as received, with its JWS header, e.g. the `x5c` its signature was verified with, whose authority
         * key identifiers DCQL `trusted_authorities` of type `aki` match (OpenID4VP 1.0, 6.1.1). Trusting that chain
         * is a separate check.
         */
        val signed: JwsCompactTyped<VerifiableCredentialJws>,
    ) : ValidatedCredential {
        /** The payload of [signed]. */
        val credential: VerifiableCredentialJws get() = signed.payload
    }

    data class SdJwtVc(
        val credential: VerifiableCredentialSdJwt,
        /** The SD-JWT with every supplied disclosure applied. */
        val decoded: SdJwtDecoded,
    ) : ValidatedCredential {
        @Deprecated("Read the SD-JWT from its decoded view", ReplaceWith("decoded.sdJwtSigned"))
        val sdJwtSigned: SdJwtSigned get() = decoded.sdJwtSigned

        @Deprecated("Read the claims from the decoded view", ReplaceWith("decoded.reconstructedJsonObject"))
        val reconstructedJsonObject: JsonObject get() = decoded.reconstructedJsonObject

        @Deprecated("Read the disclosures from the decoded view", ReplaceWith("decoded.validDisclosures"))
        val disclosures: Map<String, SelectiveDisclosureItem> get() = decoded.validDisclosures
    }

    data class IsoMdoc(val issuerSigned: IssuerSigned) : ValidatedCredential
}

/** The representation of this credential. */
val ValidatedCredential.representation: CredentialRepresentation
    get() = when (this) {
        is ValidatedCredential.VcJwt -> CredentialRepresentation.PLAIN_JWT
        is ValidatedCredential.SdJwtVc -> CredentialRepresentation.SD_JWT
        is ValidatedCredential.IsoMdoc -> CredentialRepresentation.ISO_MDOC
    }

/**
 * The [report] of validating a credential, and the [credential] if it has been accepted.
 * An unverified value is never exposed as validated: [credential] is present if and only if the report is accepted.
 */
data class CredentialValidationResult @JvmOverloads constructor(
    val report: ValidationReport,
    val credential: ValidatedCredential?,
    /**
     * The credential whatever the decision of [report], if every check no policy relaxes passed, see
     * [isIntactCredential]: it can be parsed, the issuer signed it, it is of the expected type, every disclosed item
     * is intact, and it is bound to the holder if required. But its issuer may not be trusted, it may be expired or
     * revoked, or miss claims its type requires. Use it only to continue after showing the report to the user, e.g.
     * to store a credential the user accepts nonetheless, never as an accepted credential.
     */
    val unacceptedCredential: ValidatedCredential? = credential,
) {
    init {
        require(report.checks is CredentialChecks) { "Report has to be a credential report" }
        require((credential != null) == (report.decision == ValidationDecision.ACCEPTED)) {
            "A credential is present if and only if the report is accepted"
        }
        require(credential == null || credential == unacceptedCredential) {
            "An accepted credential is the unaccepted credential too"
        }
        require(unacceptedCredential == null || report.isIntactCredential()) {
            "An unaccepted credential is only present for an intact credential"
        }
    }
}

/**
 * The [validation] of a credential to store, and the [storedEntry] if it has been stored: because it has been
 * accepted, or because the user accepted its report, see [CredentialValidationResult.unacceptedCredential].
 */
data class CredentialStorageResult(
    val validation: CredentialValidationResult,
    val storedEntry: SubjectCredentialStore.StoreEntry?,
) {
    init {
        require(storedEntry == null || validation.unacceptedCredential != null) {
            "Only an accepted or intact credential is stored"
        }
    }
}
