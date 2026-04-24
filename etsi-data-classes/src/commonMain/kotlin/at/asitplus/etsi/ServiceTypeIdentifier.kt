package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ServiceTypeIdentifier(
    val uniformResourceIdentifier: Rfc3986UniformResourceIdentifier,
) {
    val string: String
        get() = uniformResourceIdentifier.string
}