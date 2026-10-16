package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlin.jvm.JvmInline

/** An open associated-body extension (TS 119 602, 6.5.5.1.7). */
@Serializable
@JvmInline
value class AssociatedBodyInformationExtension(
    /** Extension content as defined by its originating scheme or profile, retained without modification. */
    val value: JsonElement,
)
