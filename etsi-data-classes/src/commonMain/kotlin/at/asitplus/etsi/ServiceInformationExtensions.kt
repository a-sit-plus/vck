package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ServiceInformationExtensions(
    /** Additional service-specific information interpreted under the scheme rules (TS 119 602, 6.6.9). */
    private val list: List<ServiceInformationExtension>
): List<ServiceInformationExtension> by list {
    init {
        require(list.isNotEmpty()) { "Expected at least one ServiceInformationExtensions entry." }
    }

    constructor(vararg elements: ServiceInformationExtension): this(elements.toList())
}