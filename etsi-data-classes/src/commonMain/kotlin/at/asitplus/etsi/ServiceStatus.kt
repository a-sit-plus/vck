package at.asitplus.etsi

import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ServiceStatus(
    /** URI identifying the service status, with semantics defined by the scheme or profile (TS 119 602, 6.6.4). */
    val uniformResourceIdentifier: Rfc3986UniformResourceIdentifier,
) {
    /** String representation of the service-status URI. */
    val string: String
        get() = uniformResourceIdentifier.string
}