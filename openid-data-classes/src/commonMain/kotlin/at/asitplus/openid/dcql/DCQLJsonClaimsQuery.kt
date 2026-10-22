package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive

@Serializable
data class DCQLJsonClaimsQuery(
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
    init {
        requireNonEmptyValues()
    }

    fun executeClaimsQueryAgainstCredential(
        credentialStructure: DCQLCredentialClaimStructure.JsonBasedStructure,
    ): KmmResult<DCQLClaimsQueryResult.JsonResult> = catching {
        val queryResults = path.query(credentialStructure.jsonElement)
        val result = values?.let { values ->
            queryResults.filter { result ->
                val primitive = result.value as? JsonPrimitive
                primitive != null && values.any { it.matches(primitive) }
            }
        } ?: queryResults
        require(result.isNotEmpty()) {
            throw IllegalStateException("Credential does not satisfy claims query: $this")
        }
        DCQLClaimsQueryResult.JsonResult(result)
    }
}