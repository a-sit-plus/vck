package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class TrustedEntityServices(
    private val list: List<TrustedEntityService>
): List<TrustedEntityService> by list {
    constructor(vararg services: TrustedEntityService): this(services.toList())
}

