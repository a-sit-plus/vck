package at.asitplus.wallet.lib.data.rfc7519.primitives

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable(with = AudienceInlineSerializer::class)
@JvmInline value class Audience(val value: List<StringOrURI>) {
    constructor(audience: StringOrURI) : this(listOf(audience))
}