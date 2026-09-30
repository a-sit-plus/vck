package at.asitplus.csc.datamodel.requests

import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject


/** CSC Data Model 1.0.0 section 9.1. */
@Serializable
data class CredentialCreationRequest(
    /** CSC Data Model 1.0.0 section 9.1: Certificate policy OID for the credential to create. */
    @SerialName("certificatePolicy")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val certificatePolicy: ObjectIdentifier? = null,
    /** CSC Data Model 1.0.0 section 9.1: Optional subject attributes for the new credential. */
    @SerialName("subjectData")
    val subjectData: JsonObject? = null,
)
