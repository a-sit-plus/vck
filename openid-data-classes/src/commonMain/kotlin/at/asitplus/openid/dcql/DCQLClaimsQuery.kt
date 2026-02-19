package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

@Serializable(with = DCQLClaimsQuerySerializer::class)
sealed interface DCQLClaimsQuery {
    /**
     * OID4VP draft 23: id: REQUIRED if claim_sets is present in the Credential Query; OPTIONAL
     * otherwise. A string identifying the particular claim. The value MUST be a non-empty string
     * consisting of alphanumeric, underscore (_) or hyphen (-) characters. Within the particular
     * claims array, the same id MUST NOT be present more than once.
     */
    val id: DCQLClaimsQueryIdentifier?

    /**
     * OID4VP draft 23: values: OPTIONAL. An array of strings, integers or boolean values that
     * specifies the expected values of the claim. If the values property is present, the Wallet
     * SHOULD return the claim only if the type and value of the claim both match for at least one
     * of the elements in the array. Details of the processing rules are defined in Section 6.3.1.1.
     */
    val values: List<DCQLExpectedClaimValue>?

    /**
     * OID4VP 1.0: REQUIRED The value MUST be a non-empty array representing a claims path pointer that specifies the
     * path to a claim within the Credential, as defined in Section 7.
     */
    val path: DCQLClaimsPathPointer

    object SerialNames {
        const val ID = "id"
        const val VALUES = "values"
        const val PATH = "path"
    }

    fun executeClaimsQueryAgainstCredential(
        credentialStructure: DCQLCredentialClaimStructure,
    ): KmmResult<DCQLClaimsQueryResult>
}


@Serializable
data class DCQLAmbiguousClaimsQuery(
    @SerialName(DCQLClaimsQuery.SerialNames.ID)
    override val id: DCQLClaimsQueryIdentifier? = null,
    @SerialName(DCQLClaimsQuery.SerialNames.VALUES)
    override val values: List<DCQLExpectedClaimValue>? = null,
    /**
     * OID4VP draft 23: path: REQUIRED if the Credential Format uses a JSON-based claims structure
     * (e.g., IETF SD-JWT VC and W3C Verifiable Credentials); MUST NOT be present otherwise. The
     * value MUST be a non-empty array representing a claims path pointer that specifies the path
     * to a claim within the Verifiable Credential, as defined in Section 6.4.
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
            ).executeJsonClaimsQueryAgainstCredential(
                credentialStructure = credentialStructure,
            ).getOrThrow().also {
                if (it.nodeList.isEmpty()) {
                    throw IllegalStateException("Credential does not satisfy claims query: $this")
                }
            }

            is DCQLCredentialClaimStructure.IsoMdocStructure -> DCQLIsoMdocClaimsQuery(
                id = id,
                path = path,
                values = values
            ).executeIsoMdocClaimsQueryAgainstCredential(
                credentialStructure = credentialStructure,
            ).getOrThrow()
        }
    }
}
