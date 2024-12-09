package at.asitplus.wallet.lib.data

import kotlin.jvm.JvmInline

sealed interface WebToken {
    @JvmInline
    value class JsonWebToken(val value: String) : WebToken
    @JvmInline
    value class CborWebToken(val value: ByteArray) : WebToken
}