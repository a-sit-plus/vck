package at.asitplus.etsi

import at.asitplus.testballoon.matrix.matrixSuite
import com.goncalossilva.resources.Resource
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

/**
 * Decodes the lists of trusted entities in `src/commonTest/resources/lote`, which are also read by the tests of `vck`.
 */
val ListOfTrustedEntitiesDeserializationTest by matrixSuite {

    val publishedLists = listOf(
        "pid-providers-seq4.json",
        "pid-providers-seq9.json",
        "mdl-providers-seq2.json",
        "wallet-providers-seq2.json",
        "wrpac-providers-seq2.json",
    ).associateWith { Resource("lote/$it").readText() }

    testSuite("decode published lists") {
        publishedLists.asData(nameFn = { entry -> entry.first }) test { entry ->
            Json.decodeFromString<ListOfTrustedEntities>(entry.second)
        }
    }

    testSuite("reject a service with an empty ServiceDigitalIdentity") {
        publishedLists.asData(nameFn = { entry -> entry.first }) test { entry ->
            shouldThrow<IllegalArgumentException> {
                Json.decodeFromString<ListOfTrustedEntities>(withEmptyServiceDigitalIdentity(entry.second))
            }.message shouldBe "Expected at least one service digital identifier."
        }
    }
}

/** Empties the `ServiceDigitalIdentity` of the first service of the first trusted entity in [lote]. */
private fun withEmptyServiceDigitalIdentity(lote: String): String {
    val list = Json.parseToJsonElement(lote).jsonObject
    val entity = list.getValue("TrustedEntitiesList").jsonArray.first().jsonObject
    val service = entity.getValue("TrustedEntityServices").jsonArray.first().jsonObject
    val information = service.getValue("ServiceInformation").jsonObject
    val emptiedService = service.with(
        "ServiceInformation",
        information.with("ServiceDigitalIdentity", JsonObject(emptyMap()))
    )
    val emptiedEntity = entity.with(
        "TrustedEntityServices",
        entity.getValue("TrustedEntityServices").jsonArray.withFirst(emptiedService)
    )
    return list.with(
        "TrustedEntitiesList",
        list.getValue("TrustedEntitiesList").jsonArray.withFirst(emptiedEntity)
    ).toString()
}

private fun JsonObject.with(key: String, value: JsonElement) = JsonObject(this + (key to value))

private fun JsonArray.withFirst(value: JsonElement) = JsonArray(listOf(value) + drop(1))
