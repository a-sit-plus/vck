package at.asitplus.openid

import io.ktor.http.ContentType
import io.ktor.http.parseHeaderValue

sealed interface TokenIntrospectionResponse {

    companion object {
        /** Selects the supported response format with the highest effective quality. */
        fun parseAcceptHeader(
            acceptHeader: String?,
            defaultResponseFormat: ContentType,
        ): ContentType {
            val entries = parseHeaderValue(acceptHeader ?: ContentType.Any.toString()).map {
                val mediaRange = it.params
                    .filterNot { parameter -> parameter.name.equals("q", ignoreCase = true) }
                    .fold(ContentType.parse(it.value)) { contentType, parameter ->
                        contentType.withParameter(parameter.name, parameter.value)
                    }
                AcceptHeaderEntry(
                    mediaRange = mediaRange,
                    quality = it.quality,
                )
            }

            val candidatesWithEffectiveQuality = listOf(
                TokenIntrospectionResponseJwt.contentType,
                TokenIntrospectionResponseJson.contentType,
            ).mapNotNull { candidate ->
                entries.filter { candidate.match(it.mediaRange) }
                    .maxWithOrNull(
                        compareBy<AcceptHeaderEntry> { it.mediaRange.typeSpecificity }
                            .thenBy { it.mediaRange.parameters.size }
                    )
                    ?.quality
                    ?.let { candidate to it }
            }

            val highestQuality = candidatesWithEffectiveQuality
                .maxOfOrNull { it.second }
                ?.takeIf { it > 0.0 }
                ?: throw IllegalArgumentException(
                    "The Accept header does not contain a supported response format."
                )

            val preferredCandidates = candidatesWithEffectiveQuality
                .filter { it.second == highestQuality }
                .map { it.first }

            return defaultResponseFormat.takeIf { it in preferredCandidates }
                ?: preferredCandidates.first()
        }

        private data class AcceptHeaderEntry(
            val mediaRange: ContentType,
            val quality: Double,
        )

        private val ContentType.typeSpecificity: Int
            get() = when {
                contentType == "*" -> 0
                contentSubtype == "*" -> 1
                else -> 2
            }

    }
}
