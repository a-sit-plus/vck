package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ServiceHistory(
    /** Historical status entries recorded for the recognized service (TS 119 602, 6.4.4). */
    private val list: List<ServiceHistoryInstance>
): List<ServiceHistoryInstance> by list {
    init {
        require(list.isNotEmpty()) { "Expected at least one ServiceHistory entry." }
    }

    constructor(vararg services: ServiceHistoryInstance): this(services.toList())
}

