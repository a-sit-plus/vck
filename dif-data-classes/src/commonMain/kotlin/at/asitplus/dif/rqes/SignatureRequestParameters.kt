@file:UseSerializers(SignatureRequestParameterSerializer::class)

package at.asitplus.dif.rqes

import at.asitplus.dif.rqes.CollectionEntries.Document
import at.asitplus.dif.rqes.CollectionEntries.DocumentDigestEntries.CscDocumentDigest
import at.asitplus.dif.rqes.Enums.OperationModeEnum
import at.asitplus.dif.rqes.Enums.SignatureQualifier
import at.asitplus.dif.rqes.Serializer.SignatureRequestParameterSerializer
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers

@Serializable(with = SignatureRequestParameterSerializer::class)
sealed interface SignatureRequestParameters {
    /**
     * The credentialID as defined in the Input parameter table in `/credentials/info`
     */
    val credentialId: String?

    /**
     * The Signature Activation Data returned by the Credential Authorization
     * methods. Not needed if the signing application has passed an access token in
     * the “Authorization” HTTP header with scope “credential”, which is also good for
     * the credential identified by credentialID.
     * Note: For backward compatibility, signing applications MAY pass access tokens
     * with scope “credential” in this parameter.
     */
    val sad: String?

    /**
     * The type of operation mode requested to the remote signing server
     * The default value is “S”, so if the parameter is omitted then the remote signing
     * server will manage the request in synchronous operation mode.
     */
    val operationMode: OperationModeEnum?

    /**
     * Maximum period of time, expressed in milliseconds, until which the server
     * SHALL keep the request outcome(s) available for the client application retrieval.
     * This parameter MAY be specified only if the parameter operationMode is “A”.
     */
    val validityPeriod: Int?

    /**
     * Value of one location where the server will notify the signature creation
     * operation completion, as an URI value. This parameter MAY be specified only if
     * the parameter operationMode is “A”.
     */
    val responseUri: String?

    /**
     * The clientData as defined in the Input parameter table in `oauth2/authorize`
     * TODO double check
     */
    val clientData: String?
}

@Serializable
data class SignHashParameters(

    @SerialName("credentialID")
    override val credentialId: String,

    @SerialName("SAD")
    override val sad: String? = null,

    @SerialName("operationMode")
    override val operationMode: OperationModeEnum = OperationModeEnum.SYNCHRONOUS,

    @SerialName("validity_period")
    override val validityPeriod: Int? = null,

    @SerialName("response_uri")
    override val responseUri: String? = null,

    @SerialName("clientData")
    override val clientData: String? = null,

    /**
     * Input-type is JsonArray - do not use HashesSerializer!
     * One or more base64-encoded hash values to be signed
     */
    @SerialName("hashes")
    val hashes: Hashes,

    /**
     * String containing the OID of the hash algorithm used to generate the hashes
     */
    @SerialName("hashAlgorithmOID")
    val hashAlgorithmOid: ObjectIdentifier? = null,

    /**
     * The OID of the algorithm to use for signing. It SHALL be one of the values
     * allowed by the credential as returned in keyAlgo as defined in `credentials/info` or as defined
     * in `credentials/list`
     */
    @SerialName("signAlgo")
    val signAlgo: ObjectIdentifier? = null,

    /**
     * TODO: The Base64-encoded DER-encoded ASN.1 signature parameters, if required by
     * the signature algorithm. Some algorithms like RSASSA-PSS, as defined in RFC8017,
     * may require additional parameters
     */
    @SerialName("signAlgoParams")
    val signAlgoParams: String? = null,

    ) : SignatureRequestParameters {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SignHashParameters
        if (!hashes.contentEquals(other.hashes)) return false
        if (credentialId != other.credentialId) return false
        if (sad != other.sad) return false
        if (operationMode != other.operationMode) return false
        if (validityPeriod != other.validityPeriod) return false
        if (responseUri != other.responseUri) return false
        if (clientData != other.clientData) return false
        if (hashAlgorithmOid != other.hashAlgorithmOid) return false
        if (signAlgo != other.signAlgo) return false
        if (signAlgoParams != other.signAlgoParams) return false

        return true
    }

    override fun hashCode(): Int {
        var result = hashes.contentHashCode()
        result = 31 * result + credentialId.hashCode()
        result = 31 * result + (sad?.hashCode() ?: 0)
        result = 31 * result + operationMode.hashCode()
        result = 31 * result + (validityPeriod ?: 0)
        result = 31 * result + (responseUri?.hashCode() ?: 0)
        result = 31 * result + (clientData?.hashCode() ?: 0)
        result = 31 * result + (hashAlgorithmOid?.hashCode() ?: 0)
        result = 31 * result + (signAlgo?.hashCode() ?: 0)
        result = 31 * result + (signAlgoParams?.hashCode() ?: 0)
        return result
    }
}

@Serializable
data class SignDocParameters(

    @SerialName("credentialID")
    override val credentialId: String? = null,

    @SerialName("SAD")
    override val sad: String? = null,

    @SerialName("operationMode")
    override val operationMode: OperationModeEnum = OperationModeEnum.SYNCHRONOUS,

    @SerialName("validity_period")
    override val validityPeriod: Int? = null,

    @SerialName("response_uri")
    override val responseUri: String? = null,

    @SerialName("clientData")
    override val clientData: String? = null,

    /**
     * Identifier of the signature type to be created, e.g. “eu_eidas_qes” to denote
     * a Qualified Electronic Signature according to eIDAS
     */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,

    val documentDigests: Collection<CscDocumentDigest>? = null,

    val documents: Collection<Document>? = null,

    /**
     * This parameter SHALL be set to “true” to request the service to return the
     * “validationInfo”. The default value is “false”, i.e. no
     * “validationInfo” info is provided.
     */
    @SerialName("returnValidationInformation")
    val returnValidationInformation: Boolean = false,
) : SignatureRequestParameters