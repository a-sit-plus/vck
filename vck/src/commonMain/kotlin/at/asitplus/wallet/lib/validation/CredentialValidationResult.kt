package at.asitplus.wallet.lib.validation

import at.asitplus.iso.IssuerSigned
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
    data class VcJwt(val credential: VerifiableCredentialJws) : ValidatedCredential

    data class SdJwtVc(
        val sdJwtSigned: SdJwtSigned,
        val credential: VerifiableCredentialSdJwt,
        /** Claims of the issuer-signed payload with every supplied disclosure applied. */
        val reconstructedJsonObject: JsonObject,
        /** Map of serialized disclosure (as [String]) to parsed item, for every supplied disclosure. */
        val disclosures: Map<String, SelectiveDisclosureItem>,
    ) : ValidatedCredential

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
