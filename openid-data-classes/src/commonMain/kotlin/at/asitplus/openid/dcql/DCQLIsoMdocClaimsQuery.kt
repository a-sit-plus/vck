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

    @Deprecated("Renamed", ReplaceWith("executeClaimsQueryAgainstCredential(credentialStructure)"))
    fun executeIsoMdocClaimsQueryAgainstCredential(
        credentialStructure: DCQLCredentialClaimStructure.IsoMdocStructure,
    ) = executeClaimsQueryAgainstCredential(credentialStructure)

    fun executeClaimsQueryAgainstCredential(
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