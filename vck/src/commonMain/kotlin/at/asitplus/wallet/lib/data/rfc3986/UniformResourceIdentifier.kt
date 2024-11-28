package at.asitplus.wallet.lib.data.rfc3986

import io.ktor.http.Url
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

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
}

