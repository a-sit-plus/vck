package at.asitplus.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import io.ktor.http.ContentType
import io.ktor.http.parseAndSortContentTypeHeader

sealed interface TokenIntrospectionResponse {

    companion object {
        /** Selects the supported response format with the highest effective quality. */
        fun parseAcceptHeader(
            acceptHeader: String?,
            defaultResponseFormat: ContentType,
        ): KmmResult<ContentType> = catching {
            val entries = parseAndSortContentTypeHeader(acceptHeader ?: ContentType.Any.toString()).map {
                val parsedContentType = ContentType.parse(it.value)
                ContentType(
                    parsedContentType.contentType,
                    parsedContentType.contentSubtype,
                    it.params.takeWhile { parameter -> !parameter.name.equals("q", ignoreCase = true) },
                ) to it.quality
            }

            val candidatesWithEffectiveQuality = listOf(
                TokenIntrospectionResponseJwt.contentType,
                TokenIntrospectionResponseJson.contentType,
            ).mapNotNull { candidate ->
                entries.filter { candidate.match(it.first) }
                    .reduceOrNull { current, next ->
                        val currentMediaRange = current.first
                        val nextMediaRange = next.first
                        if (
                            nextMediaRange.match(currentMediaRange) &&
                            !currentMediaRange.match(nextMediaRange)
                        ) next else current
                    }
                    ?.second
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

            defaultResponseFormat.takeIf { it in preferredCandidates }
                ?: preferredCandidates.first()
        }

    }
}
