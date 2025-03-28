package at.asitplus.rqes

import at.asitplus.rqes.enums.OperationMode
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject


@Deprecated("Renamed", ReplaceWith("SignDocParameters"))
typealias SignDocResponse = SignDocResponseParameters


/**
 * CSC API v2.0.0.2
 * Data class defined in Ch. 11.11
 * Response to [SignDocRequestParameters].
 */
@Serializable
data class SignDocResponseParameters(
    /**
     * REQUIRED-CONDITIONAL.
     * One or more Base64-encoded signatures enveloped within the
     * documents. This element SHALL carry a value only if the client application
     * requested the creation of signature(s) enveloped within the signed
     * document(s) and when when [SignDocRequestParameters.operationMode] is not [OperationMode.ASYNCHRONOUS].
     */
    @SerialName("DocumentWithSignature")
    val documentWithSignature: List<String>? = null,

    /**
     * REQUIRED-CONDITIONAL.
     * One or more Base64-encoded signatures detached from the documents.
     * This element SHALL carry a value only if the client application requested
     * the creation of detached signature(s) and
     * when [SignDocRequestParameters.operationMode] is not [OperationMode.ASYNCHRONOUS].
     */
    @SerialName("SignatureObject")
    val signatureObject: List<String>? = null,

    /**
     * REQUIRED-CONDITIONAL.
     * Arbitrary string value generated by the server uniquely identifying the response
     * originated from the server itself. This value SHALL be returned when operationMode is
     * when [SignDocRequestParameters.operationMode] is [OperationMode.ASYNCHRONOUS].
     */
    @SerialName("responseID")
    val responseId: String? = null,

    /**
     * REQUIRED-CONDITIONAL.
     * The validationInfo is a JSON Object containing validation data that SHALL
     * be included in the signing response if
     * [SignDocRequestParameters.returnValidationInformation] was [Boolean.true].
     */
    @SerialName("validationInfo")
    val validationInfo: JsonObject? = null,
) : QtspSignatureResponse