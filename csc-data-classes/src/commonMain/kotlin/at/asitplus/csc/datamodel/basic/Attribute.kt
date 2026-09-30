package at.asitplus.csc.datamodel.basic

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model 1.0.0 section 7.2. */
@Serializable
data class Attribute(
    /** CSC Data Model 1.0.0 section 7.2: Name of the signed attribute. */
    @SerialName("attribute_name")
    val attributeName: AttributeName,
    /** CSC Data Model 1.0.0 section 7.2: Optional value of the signed attribute. */
    @SerialName("attribute_value")
    val attributeValue: String? = null,
)

/**
 * CSC attribute names supported by this implementation.
 * Unsupported attributes are rejected.
 *
 * The RSSP SHOULD list supported and required attributes/properties in a
 * signature creation policy.
 */
@Serializable
enum class AttributeName {
    @SerialName("SignedData.certificates")
    CERTIFICATES,

    @SerialName("signing-time")
    SIGNING_TIME,

    @SerialName("content-type")
    CONTENT_TYPE,

    @SerialName("message-digest")
    MESSAGE_DIGEST,
}
