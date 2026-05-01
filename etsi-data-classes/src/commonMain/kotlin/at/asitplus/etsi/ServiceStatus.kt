package at.asitplus.etsi

import at.asitplus.rfc.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ServiceStatus(
    val uniformResourceIdentifier: Rfc3986UniformResourceIdentifier,
) {
    val string: String
        get() = uniformResourceIdentifier.string
}