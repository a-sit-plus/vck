package at.asitplus.wallet.lib.data.rfc3986

import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline
import kotlin.jvm.JvmName
import kotlin.jvm.JvmStatic

/**
 * specification: https://www.rfc-editor.org/rfc/rfc3986
 *
 * TODO: possibly replace with rfc3986 conforming implementation if found.
 *  Using ktor url for now, but there is no information on what specification is used there..
 */
@Serializable
@JvmInline value class UniformResourceIdentifier(
    @Serializable(with = KtorUrlSerializer::class)
    private val url: Url
) {
    constructor(string: String) : this(Url(string))

    val string: String
        get() = url.toString()

    companion object {
        /** For JVM callers which can't access value class constructors directly */
        @JvmStatic
        @JvmName("fromString")
        fun fromString(string: String) = UniformResourceIdentifier(string)
    }
}

fun String.toUri() = UniformResourceIdentifier(this)
