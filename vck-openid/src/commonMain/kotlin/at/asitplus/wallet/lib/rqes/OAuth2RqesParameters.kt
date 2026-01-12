package at.asitplus.wallet.lib.rqes

import at.asitplus.csc.Hashes
import at.asitplus.csc.contentEquals
import at.asitplus.csc.contentHashCode
import at.asitplus.csc.enums.SignatureQualifier
import at.asitplus.csc.serializers.HashesSerializer
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.JsonWebToken
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Parameters used for remote qualified electronic signature (RQES) OAuth2 authorization.
 * Use to group required and optional CSC fields when building authorization requests.
 */
sealed class OAuth2RqesParameters {
    data class CredentialRequired(
        /**
         * CSC: REQUIRED-"credential"
         * The identifier associated to the credential to authorize.
         * This parameter value may contain characters that are reserved, unsafe or
         * forbidden in URLs and therefore SHALL be url-encoded by the signature
         * application
         */
        @SerialName("credentialID")
        @Serializable(ByteArrayBase64UrlSerializer::class)
        val credentialID: ByteArray,

        /**
         * CSC: Required-"credential"
         * This parameter contains the symbolic identifier determining the kind of
         * signature to be created
         */
        @SerialName("signatureQualifier")
        val signatureQualifier: SignatureQualifier,

        /**
         * CSC: Required-"credential"
         * The number of signatures to authorize
         */
        @SerialName("numSignatures")
        val numSignatures: Int,

        /**
         * CSC: REQUIRED-"credential"
         * One or more base64url-encoded hash values to be signed
         */
        @SerialName("hashes")
        @Serializable(HashesSerializer::class)
        val hashes: Hashes,

        /**
         * CSC: REQUIRED-"credential"
         * String containing the OID of the hash algorithm used to generate the hashes
         */
        @SerialName("hashAlgorithmOID")
        val hashAlgorithmOid: ObjectIdentifier,
    ) : OAuth2RqesParameters() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as CredentialRequired

            if (numSignatures != other.numSignatures) return false
            if (!credentialID.contentEquals(other.credentialID)) return false
            if (signatureQualifier != other.signatureQualifier) return false
            if (!hashes.contentEquals(other.hashes)) return false
            if (hashAlgorithmOid != other.hashAlgorithmOid) return false

            return true
        }

        override fun hashCode(): Int {
            var result = numSignatures
            result = 31 * result + credentialID.contentHashCode()
            result = 31 * result + signatureQualifier.hashCode()
            result = 31 * result + hashes.contentHashCode()
            result = 31 * result + hashAlgorithmOid.hashCode()
            return result
        }
    }

    data class Optional(
        /**
         * CSC: OPTIONAL
         * A free form description of the authorization transaction in the lang language.
         * The maximum size of the string is 500 characters
         */
        @SerialName("description")
        val description: String? = null,

        /**
         * CSC: OPTIONAL
         * To restrict access to the authorization server of a remote service, this specification introduces the
         * additional account_token parameter to be used when calling the oauth2/authorize endpoint. This
         * parameter contains a secure token designed to authenticate the authorization request based on an
         * Account ID that SHALL be uniquely assigned by the signature application to the signing user or to the
         * user’s application account
         */
        @SerialName("account_token")
        val accountToken: JsonWebToken? = null,

        /**
         * CSC: OPTIONAL
         * Arbitrary data from the signature application. It can be used to handle a
         * transaction identifier or other application-spe cific data that may be useful for
         * debugging purposes
         */
        @SerialName("clientData")
        val clientData: String? = null,

        /**
         * CSC: Optional
         * Request a preferred language according to RFC 5646
         */
        @SerialName("lang")
        val lang: String? = null,
    )

}
