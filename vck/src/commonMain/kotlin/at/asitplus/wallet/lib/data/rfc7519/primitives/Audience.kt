package at.asitplus.wallet.lib.data.rfc7519.primitives

import at.asitplus.wallet.lib.data.rfc8392.primitives.StringOrURI
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable(with = AudienceInlineSerializer::class)
@JvmInline value class Audience(val value: List<StringOrURI>) {
    constructor(audience: StringOrURI) : this(listOf(audience))

    companion object {
        operator fun invoke(audience: List<String>) = Audience(audience.map { StringOrURI(it) })
        operator fun invoke(audience: String)  = Audience(StringOrURI(audience))
    }
}