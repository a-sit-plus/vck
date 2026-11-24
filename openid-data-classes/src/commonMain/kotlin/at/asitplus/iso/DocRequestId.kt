package at.asitplus.iso

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline
import kotlin.jvm.JvmStatic

/**
 * Identifies a document request of a [DeviceRequest] by its position in [DeviceRequest.docRequests], its DocRequestID,
 * which "references the DocRequests in the docRequests array, identified by its position starting from 0"
 * (ISO/IEC DIS 18013-5:2026, 10.2.5), like [at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier] identifies a
 * credential query of a DCQL query.
 *
 * Only used above the wire: [UseCase.documentSets] keeps the unsigned integers the CDDL defines.
 */
@Serializable
@JvmInline
value class DocRequestId(val index: Int) {
    init {
        require(index >= 0) { "A DocRequestID is a position starting from 0, not $index" }
    }

    override fun toString() = index.toString()

    companion object {
        /** For Java, which can not call the constructor of a value class. */
        @JvmStatic
        fun of(index: Int) = DocRequestId(index)
    }
}
