package at.asitplus.csc.datamodel.requests

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.ObjectIdentifierStringSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject


/** CSC Data Model 1.0.0 section 9.1. */
@Serializable
data class CredentialCreationRequest(
    /**
     * CSC Data Model 1.0.0 section 9.1: CONDITIONAL
     * Required when creating a credential under a specified certificate policy.
     */
    @SerialName("certificatePolicy")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val certificatePolicy: ObjectIdentifier? = null,
    /**
     * CSC Data Model 1.0.0 section 9.1: OPTIONAL
     * Subject attributes for the new credential.
     */
    @SerialName("subjectData")
    val subjectData: JsonObject? = null,
)
