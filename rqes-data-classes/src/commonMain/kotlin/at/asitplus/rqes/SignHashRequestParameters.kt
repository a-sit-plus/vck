package at.asitplus.rqes

import at.asitplus.csc.Hashes
import at.asitplus.csc.contentEquals
import at.asitplus.csc.contentHashCode
import at.asitplus.rqes.enums.OperationMode
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * CSC API v2.0.0.2
 * Data class defined in Ch. 11.10
 * Used to request the calculation of remote digital signature(s) of one or multiple hash values.
 */
@Serializable
@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.csc.SignHashRequestParameters"))
data class SignHashRequestParameters(
    /**
     * REQUIRED.
     * The credentialID as defined in the Input parameter table in `/credentials/info`
     */
    @SerialName("credentialID")
    override val credentialId: String,

    /**
     * REQUIRED-CONDITIONAL.
     * The Signature Activation Data returned by the Credential Authorization
     * methods. Not needed if the signing application has passed an access token in
     * the “Authorization” HTTP header with scope “credential”, which is also good for
     * the credential identified by credentialID.
     * Note: For backward compatibility, signing applications MAY pass access tokens
     * with scope “credential” in this parameter.
     */
    @SerialName("SAD")
    override val sad: String? = null,

    /**
     * OPTIONAL.
     * The type of operation mode requested to the remote signing server
     * The default value is “S”, so if the parameter is omitted then the remote signing
     * server will manage the request in synchronous operation mode.
     */
    @SerialName("operationMode")
    override val operationMode: OperationMode? = OperationMode.SYNCHRONOUS,

    /**
     * OPTIONAL-CONDITIONAL.
     * Maximum period of time, expressed in milliseconds, until which the server
     * SHALL keep the request outcome(s) available for the client application retrieval.
     * This parameter MAY be specified only if the parameter operationMode is “A”.
     */
    @SerialName("validity_period")
    override val validityPeriod: Int? = null,

    /**
     * OPTIONAL-CONDITIONAL.
     * Value of one location where the server will notify the signature creation
     * operation completion, as an URI value. This parameter MAY be specified only if
     * the parameter operationMode is “A”.
     */
    @SerialName("response_uri")
    override val responseUri: String? = null,

    /**
     * OPTIONAL.
     * Arbitrary data from the signature application. It can be used to handle a
     * transaction identifier or other application-spe cific data that may be useful for
     * debugging purposes
     */
    @SerialName("clientData")
    override val clientData: String? = null,

    /**
     * REQUIRED.
     * Input-type is JsonArray - do not use HashesSerializer!
     * One or more base64-encoded hash values to be signed
     */
    @SerialName("hashes")
    val hashes: Hashes,

    /**
     * REQUIRED-CONDITIONAL.
     * String containing the OID of the hash algorithm used to generate the hashes
     */
    @SerialName("hashAlgorithmOID")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val hashAlgorithmOid: ObjectIdentifier? = null,

    /**
     * REQUIRED.
     * The OID of the algorithm to use for signing. It SHALL be one of the values
     * allowed by the credential as returned in keyAlgo as defined in `credentials/info` or as defined
     * in `credentials/list`
     */
    @SerialName("signAlgo")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val signAlgoOid: ObjectIdentifier,

    /**
     * REQUIRED-CONDIIONAL.
     * The Base64-encoded DER-encoded ASN.1 signature algorithm parameters if required by
     * the signature algorithm - Necessary for RSASSA-PSS for example
     */
    @SerialName("signAlgoParams")
    @Serializable(with = at.asitplus.rqes.serializers.Asn1EncodableBase64Serializer::class)
    val signAlgoParams: Asn1Element? = null,

    ) : QtspSignatureRequest {

    @Transient
    val signAlgorithm: SignatureAlgorithm? = signAlgoOid.getSignAlgorithm(signAlgoParams)

    @Transient
    val hashAlgorithm: Digest = hashAlgorithmOid.getHashAlgorithm(signAlgorithm)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SignHashRequestParameters
        if (!hashes.contentEquals(other.hashes)) return false
        if (credentialId != other.credentialId) return false
        if (sad != other.sad) return false
        if (operationMode != other.operationMode) return false
        if (validityPeriod != other.validityPeriod) return false
        if (responseUri != other.responseUri) return false
        if (clientData != other.clientData) return false
        if (hashAlgorithmOid != other.hashAlgorithmOid) return false
        if (signAlgoOid != other.signAlgoOid) return false
        if (signAlgoParams != other.signAlgoParams) return false
        if (signAlgorithm != other.signAlgorithm) return false
        if (hashAlgorithm != other.hashAlgorithm) return false

        return true
    }

    override fun hashCode(): Int {
        var result = hashes.contentHashCode()
        result = 31 * result + (sad?.hashCode() ?: 0)
        result = 31 * result + operationMode.hashCode()
        result = 31 * result + (validityPeriod ?: 0)
        result = 31 * result + (responseUri?.hashCode() ?: 0)
        result = 31 * result + (clientData?.hashCode() ?: 0)
        result = 31 * result + credentialId.hashCode()
        result = 31 * result + (hashAlgorithmOid?.hashCode() ?: 0)
        result = 31 * result + signAlgoOid.hashCode()
        result = 31 * result + (signAlgoParams?.hashCode() ?: 0)
        result = 31 * result + (signAlgorithm?.hashCode() ?: 0)
        result = 31 * result + hashAlgorithm.hashCode()
        return result
    }
}