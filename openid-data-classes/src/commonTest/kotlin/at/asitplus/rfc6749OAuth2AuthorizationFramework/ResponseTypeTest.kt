package at.asitplus.rfc6749OAuth2AuthorizationFramework

import at.asitplus.openid.OpenIdConstants
import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

@Suppress("unused")
val ResponseTypeTest by matrixSuite {
    val commonTypes = listOf(
        OpenIdConstants.VP_TOKEN,
        OpenIdConstants.ID_TOKEN,
    )
    val commonTypeCombinations = listOf(
        listOf(
            OpenIdConstants.VP_TOKEN,
        ),
        listOf(
            OpenIdConstants.ID_TOKEN,
        ),
        commonTypes,
        commonTypes.reversed(),
    )
    "empty string is not valid" {
        shouldThrow<IllegalArgumentException> {
            ResponseType("")
        }
    }
    "common types are valid" - {
        data(commonTypes) test {
            shouldNotThrowAny {
                ResponseType(it)
            }
        }
    }
    "toString is as expected" - {
        data(commonTypes) test {
            ResponseType(it).toString() shouldBe it
        }
    }
    "common type combinations are valid and consistent between constructors" - {
        data(commonTypeCombinations) test {
            shouldNotThrowAny {
                ResponseType(it)
            } shouldBe shouldNotThrowAny {
                ResponseType(it.joinToString(" "))
            }
        }
    }
    "equality does not depend on order" - {
        data(commonTypeCombinations) test {
            ResponseType(it) shouldBe ResponseType(it.reversed())
        }
    }
    "contains works properly" - {
        data(commonTypeCombinations) test {
            val type = ResponseType(it)
            it.forEach {
                type.contains(it).shouldBeTrue()
            }
        }
    }
    "serialization works as expected" - {
        data(commonTypeCombinations) test {
            val type = ResponseType(it)
            Json.encodeToString(
                ResponseType.serializer(), // TODO: for some reason this is necessary for iOs?
                type,
            ) shouldBe Json.encodeToString(it.joinToString(" "))
        }
    }
    "deserialization works as expected" - {
        data(commonTypeCombinations) test {
            val value = it.joinToString(" ")
            val serialized = Json.encodeToString(value)
            val deserialized = Json.decodeFromString(
                ResponseType.serializer(), // TODO: for some reason this is necessary for iOs?
                serialized
            )
            ResponseType(it).toString() shouldBe value
        }
    }
    "leading spaces are not ignored" - {
        listOf(" vp_token", " vp_token id_token").asData() test {
            shouldThrow<IllegalArgumentException> {
                ResponseType(it).toString()
            }
        }
    }
    "trailing spaces are not ignored" - {
        listOf("vp_token ", "vp_token id_token ").asData() test {
            shouldThrow<IllegalArgumentException> {
                ResponseType(it).toString()
            }
        }
    }
}