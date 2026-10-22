package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonPrimitive


@Serializable
data class DCQLIsoMdocClaimsQuery(
    @SerialName(DCQLClaimsQuery.SerialNames.ID)
    override val id: DCQLClaimsQueryIdentifier? = null,
    @SerialName(DCQLClaimsQuery.SerialNames.VALUES)
    override val values: List<DCQLExpectedClaimValue>? = null,
    @SerialName(DCQLClaimsQuery.SerialNames.PATH)
    override val path: DCQLClaimsPathPointer,

    /**
     * OID4VP 1.0, B.2.4: intent_to_retain: OPTIONAL. A boolean that is equivalent to IntentToRetain variable defined in
     * Section 8.3.2.1.2.1 of [ISO.18013-5].
     *
     * ISO/IEC 18013-5, 8.3.2.1.2.1:
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
        requireNonEmptyValues()
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
        values?.let { values ->
            val json = value.toJsonForValueMatching()
            json != null && values.any { it.matches(json) }
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

/**
 * The JSON value of a data element for matching `values`. OpenID4VP 1.0, 6.3 requires the CBOR value of an ISO mdoc
 * to be converted to JSON first, see [DCQLCredentialClaimStructure.IsoMdocStructure]: a [JsonPrimitive] is used as it
 * is, and a Kotlin string, boolean or integer, whose conversion is unambiguous, as its JSON value. Other values, e.g.
 * a date that has not been converted, do not match.
 */
private fun Any.toJsonForValueMatching(): JsonPrimitive? = when (this) {
    is JsonPrimitive -> this
    is String -> JsonPrimitive(this)
    is Boolean -> JsonPrimitive(this)
    is Byte -> JsonPrimitive(toLong())
    is Short -> JsonPrimitive(toLong())
    is Int -> JsonPrimitive(toLong())
    is Long -> JsonPrimitive(this)
    is UByte -> JsonPrimitive(toLong())
    is UShort -> JsonPrimitive(toLong())
    is UInt -> JsonPrimitive(toLong())
    is ULong -> toString().toLongOrNull()?.let { JsonPrimitive(it) }
    is BigInteger -> toString().toLongOrNull()?.let { JsonPrimitive(it) }
    else -> null
}
