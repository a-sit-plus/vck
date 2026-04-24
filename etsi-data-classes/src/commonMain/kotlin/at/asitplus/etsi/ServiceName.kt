package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ServiceName(
    private val list: List<MultilingualCharacterString>
): List<MultilingualCharacterString> by list {
    constructor(vararg services: MultilingualCharacterString): this(services.toList())
}