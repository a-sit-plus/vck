package at.asitplus.wallet.lib.data.rfc9110

import kotlin.jvm.JvmInline

@JvmInline
value class HttpContentEncoding(val value: String) {
    companion object {
        fun validate(value: String) {
            // TODO()
        }
    }

    init {
        validate(value)
    }
}

