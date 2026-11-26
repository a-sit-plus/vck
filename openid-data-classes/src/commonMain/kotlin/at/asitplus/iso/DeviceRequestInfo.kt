package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * Part of the ISO/IEC DIS 18013-5:2026 standard: Additional device request info (10.2.5)
 *
 * Fails for an empty [useCases] (`? "useCases": [+UseCase]`). An instance without any value is not rejected, although
 * "If present, DeviceRequestInfo shall contain at least one key-value pair": it is also what decoding one that
 * contains only application-specific extensions (`* tstr => Ext`) results in.
 */
@Serializable
data class DeviceRequestInfo(
    @SerialName("useCases")
    val useCases: List<UseCase>? = null,
) {
    init {
        require(useCases == null || useCases.isNotEmpty()) { "useCases must not be empty if present" }
    }
}


/**
 * Part of the ISO/IEC DIS 18013-5:2026 standard: Additional device request info (10.2.5)
 *
 * To satisfy a request, the mdoc "has to satisfy at least one UseCase", every [mandatory] one, and "Exactly one
 * DocumentSet has to be satisfied" of each it satisfies. Each set of [documentSets] lists DocRequestIDs, the positions
 * of document requests in `DeviceRequest.docRequests`, starting from 0.
 *
 * Fails for an empty [documentSets], an empty document set (`"documentSets" : [+ DocumentSet]`,
 * `DocumentSet = [+ DocRequestID]`), and empty [purposeHints]
 * (`PurposeHints = {+ PurposeControllerId => PurposeCode}`).
 */
@Serializable
data class UseCase(
    @SerialName("mandatory")
    val mandatory: Boolean,
    @SerialName("documentSets")
    val documentSets: List<List<UInt>>,
    /**
     * Purpose codes by the ID of the entity that defines them, e.g. [PURPOSE_AGE_VERIFICATION] of
     * [PURPOSE_CONTROLLER_ISO], to "help the user to distinguish the different UseCase in the request".
     */
    @SerialName("purposeHints")
    val purposeHints: Map<String, Int>? = null,
) {
    init {
        require(documentSets.isNotEmpty()) { "A use case needs at least one document set" }
        require(documentSets.none { it.isEmpty() }) { "A document set of a use case is empty" }
        require(purposeHints == null || purposeHints.isNotEmpty()) { "purposeHints must not be empty if present" }
    }

    companion object {
        /** The PurposeControllerId of the purposes ISO/IEC DIS 18013-5:2026, 10.2.5 defines. */
        const val PURPOSE_CONTROLLER_ISO = "org.iso.jtc1.sc17"

        /** Identity verification, a PurposeCode of [PURPOSE_CONTROLLER_ISO] (ISO/IEC DIS 18013-5:2026). */
        const val PURPOSE_IDENTITY_VERIFICATION = 1

        /** Driving privilege verification, a PurposeCode of [PURPOSE_CONTROLLER_ISO] (ISO/IEC DIS 18013-5:2026). */
        const val PURPOSE_DRIVING_PRIVILEGE_VERIFICATION = 2

        /** Age verification, a PurposeCode of [PURPOSE_CONTROLLER_ISO] (ISO/IEC DIS 18013-5:2026). */
        const val PURPOSE_AGE_VERIFICATION = 3
    }
}
