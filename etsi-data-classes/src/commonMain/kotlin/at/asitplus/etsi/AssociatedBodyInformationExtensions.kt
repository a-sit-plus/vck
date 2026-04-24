package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class AssociatedBodyInformationExtensions(
    private val list: List<AssociatedBodyInformationExtension>
): List<AssociatedBodyInformationExtension> by list

