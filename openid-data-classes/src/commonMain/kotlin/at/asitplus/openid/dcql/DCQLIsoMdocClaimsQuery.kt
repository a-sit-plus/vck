package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialFormatEnum
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


@Serializable
data class DCQLIsoMdocClaimsQuery(
    @SerialName(DCQLClaimsQuery.SerialNames.ID)
    override val id: DCQLClaimsQueryIdentifier? = null,
    @SerialName(DCQLClaimsQuery.SerialNames.VALUES)
    override val values: List<DCQLExpectedClaimValue>? = null,

    /**
     * OID4VP draft 23: namespace: REQUIRED if the Credential Format is based on the mdoc format
     * defined in [ISO.18013-5]; MUST NOT be present otherwise. The value MUST be a string that
     * specifies the namespace of the data element within the mdoc, e.g., org.iso.18013.5.1.
     */
    @SerialName(SerialNames.NAMESPACE)
    val namespace: String,

    /**
     * OID4VP draft 23: claim_name: REQUIRED if the Credential Format is based on mdoc format
     * defined in [ISO.18013-5]; MUST NOT be present otherwise. The value MUST be a string that
     * specifies the data element identifier of the data element within the provided namespace in
     * the mdoc, e.g., first_name.
     */
    @SerialName(SerialNames.CLAIM_NAME)
    val claimName: String,
) : DCQLClaimsQuery {

    object SerialNames {
        const val NAMESPACE = "namespace"
        const val CLAIM_NAME = "claim_name"
    }

    /**
     *  6.3.1.1. Selecting Claims
     *
     * The following rules apply for selecting claims via claims and claim_sets:
     * If claims is absent, the Verifier requests all claims existing in the Credential.
     * If claims is present, but claim_sets is absent, the Verifier requests all claims listed in
     * claims. If both claims and claim_sets are present, the Verifier requests one combination of
     * the claims listed in claim_sets. The order of the options conveyed in the claim_sets array
     * expresses the Verifier's preference for what is returned; the Wallet MUST return the first
     * option that it can satisfy. If the Wallet cannot satisfy any of the options, it MUST NOT
     * return any claims.When a Claims Query contains a restriction on the values of a claim, the
     * Wallet SHOULD NOT return the claim if its value does not match at least one of the elements
     * in values i.e., the claim should be treated the same as if it did not exist in the
     * Credential. Implementing this restriction may not be possible in all cases, for example,
     * if the Wallet does not have access to the claim value before presentation or user consent or
     * if another component routing the request to the Wallet does not have access to the claim
     * value. Therefore, Verifiers must treat restrictions expressed using values as a best-effort
     * way to improve user privacy, but MUST NOT rely on it for security checks.The purpose of the
     * claim_sets syntax is to provide a way for a verifier to describe alternative ways a given
     * credential can satisfy the request. The array ordering expresses the Verifier's preference
     * for how to fulfill the request. The first element in the array is the most preferred and the
     * last element in the array is the least preferred. Verifiers SHOULD use the principle of
     * least information disclosure to influence how they order these options. For example, a proof
     * of age request should prioritize requesting an attribute like age_over_18 over an attribute
     * like birth_date. The claim_sets syntax is not intended to define options the user can choose
     * from, see Section 6.3.1.3 for more information.If the Wallet cannot deliver all claims
     * requested by the Verifier according to these rules, it MUST NOT return the respective
     * Credential.
     */
    fun <Credential : Any> executeIsoMdocClaimsQueryAgainstCredential(
        credentialQuery: DCQLCredentialQuery,
        credential: Credential,
        credentialStructureExtractor: (Credential) -> DCQLCredentialClaimStructure.IsoMdocStructure,
    ): KmmResult<DCQLClaimsQueryResult> = catching {
        if (credentialQuery.format != CredentialFormatEnum.MSO_MDOC) {
            throw IllegalArgumentException("Inconsistent credential format and claim query")
        }
        val credentialStructure = credentialStructureExtractor(credential)

        val value = credentialStructure.namespaceClaimValueMap[namespace]!![claimName]!!
        values?.any {
            catching {
                when (it) {
                    is DCQLExpectedClaimValue.IntegerValue -> when (value) {
                        is Byte -> value == it.long
                        is UByte -> value == it.long
                        is Short -> value == it.long
                        is UShort -> value == it.long
                        is Int -> value == it.long
                        is UInt -> value == it.long
                        is Long -> value == it.long
                        is ULong -> value == it.long
                        is BigInteger -> value == it.long
                        else -> false
                    }

                    is DCQLExpectedClaimValue.BooleanValue -> value as Boolean == it.boolean
                    is DCQLExpectedClaimValue.StringValue -> value as String == it.string
                }
            }.getOrNull() ?: false
        }?.let {
            if (it == false) {
                throw IllegalStateException("Value $value (${value::class}) to be queried is not expected: $values")
            }
        }

        DCQLClaimsQueryResult.IsoMdocResult(
            namespace = namespace,
            claimName = claimName,
            claimValue = value,
        )
    }
}