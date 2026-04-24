package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ServiceHistory(
    private val list: List<ServiceHistoryInstance>
): List<ServiceHistoryInstance> by list {
    constructor(vararg services: ServiceHistoryInstance): this(services.toList())
}

