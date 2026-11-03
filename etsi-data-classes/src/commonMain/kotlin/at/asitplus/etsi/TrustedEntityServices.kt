package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class TrustedEntityServices(
    /** Recognized services and their current information and status histories (TS 119 602, 6.4.2). */
    private val list: List<TrustedEntityService>
): List<TrustedEntityService> by list {
    init {
        require(list.isNotEmpty()) { "Expected at least one TrustedEntityServices entry." }
    }

    constructor(vararg services: TrustedEntityService): this(services.toList())
}

