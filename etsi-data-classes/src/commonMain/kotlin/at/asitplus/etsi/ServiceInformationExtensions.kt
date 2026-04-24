package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ServiceInformationExtensions(
    private val list: List<ServiceInformationExtension>
): List<ServiceInformationExtension> by list {
    constructor(vararg elements: ServiceInformationExtension): this(elements.toList())
}