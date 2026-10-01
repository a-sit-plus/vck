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
     * OPTIONAL. A boolean that is equivalent to IntentToRetain variable defined in
     * Section 8.3.2.1.2.1 of ISO 18013-5:
     *
     * For each requested data element, this variable indicates whether the mdoc verifier
     * intends to retain the received data element. The mdoc verifier shall not retain any data, including
     * digests and signatures, or derived data received from the mdoc, except for data elements for which the
     * IntentToRetain flag was set to true in the request. To retain is defined as “to store for a period longer
     * than necessary to conduct the transaction in realtime”.
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