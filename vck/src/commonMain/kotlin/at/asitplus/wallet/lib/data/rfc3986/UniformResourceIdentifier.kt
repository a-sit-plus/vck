package at.asitplus.wallet.lib.data.rfc3986

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * specification: https://www.rfc-editor.org/rfc/rfc3986
 */
@Serializable
@JvmInline value class UniformResourceIdentifier(val value: String) {
    companion object {
        fun validate(value: String) {
            // TODO, or possibly replace with typealias if existing implementation is found?
        }
    }

    init {
        validate(value)
    }

    override fun toString() = value
}

