package at.asitplus.wallet.lib.data.rfc7519

import at.asitplus.wallet.lib.data.rfc7519.primitives.Audience
import at.asitplus.wallet.lib.data.rfc7519.primitives.AudienceInlineSerializer
import at.asitplus.wallet.lib.data.rfc7519.primitives.StringOrURI
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.decodeFromHexString
import kotlinx.serialization.encodeToHexString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json


@ExperimentalSerializationApi
class AudienceSerializerTest : FreeSpec({
    "simple tests" - {
        val values = listOf(
            listOf(StringOrURI("Test")),
            StringOrURI("Test"),
            "Test",
            Audience(StringOrURI("Test")),
            Audience(listOf(StringOrURI("Test"))),
        )
        withData(
            data = values.mapIndexed { index, it ->
                index.toString() to it
            }.toMap()
        ) { value ->
            run {
                @Suppress("UNCHECKED_CAST") val serialized = when (value) {
                    is String -> Cbor.encodeToHexString(value)
                    is StringOrURI -> Cbor.encodeToHexString(value)
                    is Audience -> Cbor.encodeToHexString(value)
                    else -> Cbor.encodeToHexString(value as List<StringOrURI>)
                }

                Cbor.decodeFromHexString(AudienceInlineSerializer, serialized) shouldBe run {
                    @Suppress("UNCHECKED_CAST") when (val it = value) {
                        is List<*> -> Audience(value as List<StringOrURI>)
                        is String -> Audience(listOf(StringOrURI(it)))
                        is StringOrURI -> Audience(listOf(it))
                        is Audience -> Audience(it.value)
                        else -> throw IllegalStateException("Unexpected instance")
                    }
                }
            }

            run {
                @Suppress("UNCHECKED_CAST") val serialized = when (value) {
                    is String -> Json.encodeToString(value)
                    is StringOrURI -> Json.encodeToString(value)
                    is Audience -> Json.encodeToString(value)
                    else -> Json.encodeToString(value as List<StringOrURI>)
                }

                Json.decodeFromString(AudienceInlineSerializer, serialized) shouldBe run {
                    @Suppress("UNCHECKED_CAST") when (val it = value as Any) {
                        is List<*> -> Audience(value as List<StringOrURI>)
                        is String -> Audience(listOf(StringOrURI(it)))
                        is StringOrURI -> Audience(listOf(it))
                        is Audience -> Audience(it.value)
                        else -> throw IllegalStateException("Unexpected instance")
                    }
                }
            }
        }
    }
})