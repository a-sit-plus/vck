@file:UseSerializers(UrlSerializer::class)

package at.asitplus.dif.rqes

import kotlinx.serialization.UseSerializers

/**
 * Checks that either both strings are present or null
 */
internal infix fun String?.iff(other: String?): Boolean =
    (this != null && other != null) or (this == null && other == null)
