package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DCQLAmbiguousClaimsQuery(
    @SerialName(DCQLClaimsQuery.SerialNames.ID)
    override val id: DCQLClaimsQueryIdentifier? = null,
    @SerialName(DCQLClaimsQuery.SerialNames.VALUES)
    override val values: List<DCQLExpectedClaimValue>? = null,
    /**
     * OID4VP 1.0, 6.3: path: REQUIRED The value MUST be a non-empty array representing a claims path pointer that
     * specifies the path to a claim within the Credential, as defined in Section 7.
     */
    @SerialName(DCQLClaimsQuery.SerialNames.PATH)
    override val path: DCQLClaimsPathPointer
) : DCQLClaimsQuery {
    override fun executeClaimsQueryAgainstCredential(
        credentialStructure: DCQLCredentialClaimStructure,
    ): KmmResult<DCQLClaimsQueryResult> = catching {
        when (credentialStructure) {
            is DCQLCredentialClaimStructure.JsonBasedStructure -> DCQLJsonClaimsQuery(
                id = id,
                path = path,
                values = values
            ).executeClaimsQueryAgainstCredential(
                credentialStructure = credentialStructure,
            ).getOrThrow()

            is DCQLCredentialClaimStructure.IsoMdocStructure -> DCQLIsoMdocClaimsQuery(
                id = id,
                path = path,
                values = values
            ).executeClaimsQueryAgainstCredential(
                credentialStructure = credentialStructure,
            ).getOrThrow()
        }
    }
}