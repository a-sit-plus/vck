package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ServiceName(
    /** Localized names under which the trusted entity provides the service (TS 119 602, 6.6.2). */
    private val list: List<MultilingualCharacterString>
): List<MultilingualCharacterString> by list {
    init {
        require(list.isNotEmpty()) { "Expected at least one ServiceName entry." }
    }

    constructor(vararg services: MultilingualCharacterString): this(services.toList())
}