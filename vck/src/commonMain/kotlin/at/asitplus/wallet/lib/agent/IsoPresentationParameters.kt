package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.jsonpath.core.NormalizedJsonPath

@ConsistentCopyVisibility
data class IsoPresentationParameters private constructor(
    val credential: SubjectCredentialStore.StoreEntry.Iso,
    val claims: Collection<NormalizedJsonPath>,
    val zkMetadata: ZkMetadata?,
    /**
     * Requested data elements that are not returned, as the `errors` structure of the mdoc response
     * (ISO/IEC 18013-5:2021, 8.3.2.1.2.2), keyed by namespace and data element identifier.
     *
     * Currently populated for age attestations that no attestation in the credential can answer (7.2.5 step 3).
     */
    val errors: Map<String, Map<String, Int>> = emptyMap(),
) {
    companion object {
        fun create(
            credential: SubjectCredentialStore.StoreEntry.Iso,
            claims: Collection<NormalizedJsonPath>,
            zkMetadata: ZkMetadata? = null,
            errors: Map<String, Map<String, Int>> = emptyMap(),
        ): KmmResult<IsoPresentationParameters> = catching {
            if (zkMetadata?.isCompatibleWith(credential) == false) {
               throw PresentationException("Metadata incompatible with credential")
            }
            IsoPresentationParameters(credential, claims, zkMetadata, errors)
        }
    }
}