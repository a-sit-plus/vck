package at.asitplus.csc.bindings


/** Credential-format identifiers for the CSC qesApproval binding in section 7.2.1. */
object QesApprovalBinding {
    const val NAMESPACE = "org.cloudsignatureconsortium.dm.1"
    const val DATA_ELEMENT_IDENTIFIER = "qesApproval"
    const val SD_JWT_CLAIM = "$NAMESPACE.$DATA_ELEMENT_IDENTIFIER"
}

