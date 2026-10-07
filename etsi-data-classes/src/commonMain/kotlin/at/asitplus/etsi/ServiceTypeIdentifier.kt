package at.asitplus.etsi

import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ServiceTypeIdentifier(
    /** URI identifying the service type (TS 119 602, 6.6.1). */
    val uniformResourceIdentifier: Rfc3986UniformResourceIdentifier,
) {
    /** String representation of the service-type URI. */
    val string: String
        get() = uniformResourceIdentifier.string
}