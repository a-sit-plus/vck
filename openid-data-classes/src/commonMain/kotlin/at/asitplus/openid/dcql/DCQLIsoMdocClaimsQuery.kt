package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient


@Serializable
data class DCQLIsoMdocClaimsQuery(
    @SerialName(DCQLClaimsQuery.SerialNames.ID)
    override val id: DCQLClaimsQueryIdentifier? = null,
    @SerialName(DCQLClaimsQuery.SerialNames.VALUES)
    override val values: List<DCQLExpectedClaimValue>? = null,
    @SerialName(DCQLClaimsQuery.SerialNames.PATH)
    override val path: DCQLClaimsPathPointer,

    /**
     * OID4VP draft 28: OPTIONAL. A boolean that is equivalent to IntentToRetain variable defined in
     * Section 8.3.2.1.2.1 of ISO 18013-5.
     * */
    @SerialName(SerialNames.INTENT_TO_RETAIN)
    val intentToRetain: Boolean? = null,
) : DCQLClaimsQuery {
    object SerialNames {
        const val INTENT_TO_RETAIN = "intent_to_retain"
    }

    init {
        require(path.size == 2) { "`path` needs to contain exactly 2 elements " }
        require(path.all { it is NameSegment }) { "`path` must contain name segments only" }
    }

    @Transient
    val namespace = (path.first() as NameSegment).name

    @Transient
    val claimName = (path.last() as NameSegment).name

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
     * from, see Section 6.3.1.3 for more information. If the Wallet cannot deliver all claims
     * requested by the Verifier according to these rules, it MUST NOT return the respective
     * Credential.
     */
    override fun executeClaimsQueryAgainstCredential(
        credentialStructure: DCQLCredentialClaimStructure
    ): KmmResult<DCQLClaimsQueryResult> {
        require(credentialStructure is DCQLCredentialClaimStructure.IsoMdocStructure) {
            "Incompatible credential claim structure: Expected ISO MDOC but got $credentialStructure"
        }
        return executeIsoMdocClaimsQueryAgainstCredential(credentialStructure)
    }

    fun executeIsoMdocClaimsQueryAgainstCredential(
        credentialStructure: DCQLCredentialClaimStructure.IsoMdocStructure,
    ): KmmResult<DCQLClaimsQueryResult.IsoMdocResult> = catching {
        val value = credentialStructure.namespaceClaimValueMap[namespace]!![claimName]!!
        values?.any {
            when (it) {
                is DCQLExpectedClaimValue.IntegerValue -> when (value) {
                    is Byte -> value.toLong() == it.long
                    is UByte -> value.toLong() == it.long
                    is Short -> value.toLong() == it.long
                    is UShort -> value.toLong() == it.long
                    is Int -> value.toLong() == it.long
                    is UInt -> value.toLong() == it.long
                    is Long -> value == it.long
                    is ULong -> value.toLong() == it.long
                    is BigInteger -> value == BigInteger(it.long)
                    else -> false
                }

                is DCQLExpectedClaimValue.BooleanValue -> value as? Boolean == it.boolean
                is DCQLExpectedClaimValue.StringValue -> value as? String == it.string
            }
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