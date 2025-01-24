package at.asitplus.wallet.lib.rqes.helper

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.Hashes
import at.asitplus.openid.SignatureQualifier
import at.asitplus.openid.contentEquals
import at.asitplus.openid.contentHashCode
import at.asitplus.rqes.collection_entries.TransactionData
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.josef.JsonWebToken

sealed class RqesParameters {
    /**
     * Parameters defined in the CSC extension of [AuthenticationRequestParameters]
     */
    data class CscRqesParameters(
        val lang: String? = null,
        val credentialID: ByteArray? = null,
        val signatureQualifier: SignatureQualifier? = null,
        val numSignatures: Int? = null,
        val hashes: Hashes? = null,
        val hashAlgorithmOid: ObjectIdentifier? = null,
        val description: String? = null,
        val accountToken: JsonWebToken? = null,
        val clientData: String? = null,
    ) : RqesParameters() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as CscRqesParameters

            if (numSignatures != other.numSignatures) return false
            if (lang != other.lang) return false
            if (credentialID != null) {
                if (other.credentialID == null) return false
                if (!credentialID.contentEquals(other.credentialID)) return false
            } else if (other.credentialID != null) return false
            if (signatureQualifier != other.signatureQualifier) return false
            if (!hashes.contentEquals(other.hashes)) return false
            if (hashAlgorithmOid != other.hashAlgorithmOid) return false
            if (description != other.description) return false
            if (accountToken != other.accountToken) return false
            if (clientData != other.clientData) return false

            return true
        }

        override fun hashCode(): Int {
            var result = numSignatures ?: 0
            result = 31 * result + (lang?.hashCode() ?: 0)
            result = 31 * result + (credentialID?.contentHashCode() ?: 0)
            result = 31 * result + (signatureQualifier?.hashCode() ?: 0)
            result = 31 * result + (hashes?.contentHashCode() ?: 0)
            result = 31 * result + (hashAlgorithmOid?.hashCode() ?: 0)
            result = 31 * result + (description?.hashCode() ?: 0)
            result = 31 * result + (accountToken?.hashCode() ?: 0)
            result = 31 * result + (clientData?.hashCode() ?: 0)
            return result
        }

        fun toTransactionData(): TransactionData {
            TODO()
        }
    }

    /**
     * Parameters defined in the OID4VP Draft-23 extension of [AuthenticationRequestParameters]
     */
    data class Oid4VpRqesParameters(
        val transactionData: Set<TransactionData>,
    ) : RqesParameters()

}
