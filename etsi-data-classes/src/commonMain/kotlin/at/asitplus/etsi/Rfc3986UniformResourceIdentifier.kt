package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class Rfc3986UniformResourceIdentifier(
    val string: String
) {
    init {
        // TODO: implement proper grammar validation?
    }
}