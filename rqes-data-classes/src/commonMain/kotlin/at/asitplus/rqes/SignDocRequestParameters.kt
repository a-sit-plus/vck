package at.asitplus.rqes

import at.asitplus.openid.SignatureQualifier
import at.asitplus.rqes.collection_entries.DocumentDigest
import at.asitplus.rqes.collection_entries.Document
import at.asitplus.rqes.collection_entries.or
import at.asitplus.rqes.enums.OperationMode
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * CSC API v2.0.0.2
 * Data class defined in Ch. 11.11
 * Used to request the creation of one or more AdES signature(s).
 */
@Serializable
data class SignDocRequestParameters(
    /**
     * REQUIRED-CONDITIONAL.
     * The credentialID as defined in the Input parameter table in `/credentials/info`
     * At least one of the two values credentialID and signatureQualifier SHALL be
     * present. Both values MAY be present.
     */
    @SerialName("credentialID")
    override val credentialId: String? = null,

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
     * REQUIRED-CONDITIONAL.
     * Identifier of the signature type to be created, e.g. “eu_eidas_qes” to denote
     * a Qualified Electronic Signature according to eIDAS
     */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,

    /**
     * REQUIRED-CONDITIONAL.
     * An array containing JSON objects containing a hash value representing one or
     * more SDRs, the respective digest algorithm OID used to calculate this hash
     * value and further request parameters. This parameter or the
     * parameter documents MUST be present in a request.
     */
    @SerialName("documentDigests")
    val documentDigests: Collection<DocumentDigest>? = null,

    /**
     * REQUIRED-CONDITIONAL.
     * An array containing JSON objects, each of them containing a base64-encoded
     * document content to be signed and further request parameter. This
     * parameter or the parameter documentDigests MUST be present in a request.
     */
    @SerialName("documents")
    val documents: Collection<Document>? = null,

    /**
     * OPTIONAL.
     * This parameter SHALL be set to “true” to request the service to return the
     * “validationInfo”. The default value is “false”, i.e. no
     * “validationInfo” info is provided.
     */
    @SerialName("returnValidationInformation")
    val returnValidationInformation: Boolean? = false,

    ) : QtspSignatureRequest {
    init {
        require(credentialId or signatureQualifier) { "Either credentialId or signatureQualifier must not be null (both can be present)" }
        require(documentDigests or documents) { "Either documentDigests or documents must not be null (both can be present)" }
    }
}