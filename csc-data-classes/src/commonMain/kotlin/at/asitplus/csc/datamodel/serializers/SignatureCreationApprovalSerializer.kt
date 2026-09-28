package at.asitplus.csc.datamodel.serializers

import at.asitplus.csc.datamodel.authorization.SignatureCreationApproval
import kotlinx.serialization.KSerializer

/** Serializer for the regular, non-flattened CSC Signature Creation Approval object. */
object SignatureCreationApprovalSerializer : KSerializer<SignatureCreationApproval> by SignatureCreationApproval.serializer()
