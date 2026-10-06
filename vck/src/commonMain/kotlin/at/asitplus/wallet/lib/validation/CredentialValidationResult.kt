package at.asitplus.wallet.lib.validation

import at.asitplus.iso.IssuerSigned
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.jws.SdJwtSigned
import kotlinx.serialization.json.JsonObject

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

/**
 * The [report] of validating a credential, and the [credential] if it has been accepted.
 * An unverified value is never exposed as validated: [credential] is present if and only if the report is accepted.
 */
data class CredentialValidationResult(
    val report: ValidationReport,
    val credential: ValidatedCredential?,
) {
    init {
        require(report.checks is CredentialChecks) { "Report has to be a credential report" }
        require((credential != null) == (report.decision == ValidationDecision.ACCEPTED)) {
            "A credential is present if and only if the report is accepted"
        }
    }
}

/**
 * The [validation] of a credential to store, and the [storedEntry] if it has been accepted and stored.
 */
data class CredentialStorageResult(
    val validation: CredentialValidationResult,
    val storedEntry: SubjectCredentialStore.StoreEntry?,
) {
    init {
        require(storedEntry == null || validation.credential != null) { "Only an accepted credential is stored" }
    }
}
