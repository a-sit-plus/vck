package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import de.infix.testBalloon.framework.testSuite
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonPrimitive

val OidcUserInfoSerializationTest by testSuite {
    test("Basic") {
        val input = """
        {
            "sub": "testvalue-sub",
            "name": "testvalue-name"
        }
        """.trimIndent()

        val user = OidcUserInfoExtended.deserialize(input).getOrThrow()

        user.userInfo.subject shouldBe "testvalue-sub"
        user.userInfo.name shouldBe "testvalue-name"
        user.shouldHaveKey("sub").content shouldBe "testvalue-sub"
        user.shouldHaveKey("name").content shouldBe "testvalue-name"

        val serialized = joseCompliantSerializer.encodeToString(user)
        joseCompliantSerializer.decodeFromString<OidcUserInfoExtended>(serialized) shouldBe user
    }

    test("Extended attributes") {
        val input = """
        {
            "sub": "testvalue-sub",
            "name": "testvalue-name",
            "foo": "testvalue-foo",
            "${randomString()}": "${randomString()}"
        }
        """.trimIndent()

        val user = OidcUserInfoExtended.deserialize(input).getOrThrow()

        user.userInfo.subject shouldBe "testvalue-sub"
        user.userInfo.name shouldBe "testvalue-name"
        user.shouldHaveKey("sub").content shouldBe "testvalue-sub"
        user.shouldHaveKey("name").content shouldBe "testvalue-name"
        user.shouldHaveKey("foo").content shouldBe "testvalue-foo"

        val serialized = joseCompliantSerializer.encodeToString(user)
        joseCompliantSerializer.decodeFromString<OidcUserInfoExtended>(serialized) shouldBe user
    }

}
private fun OidcUserInfoExtended.shouldHaveKey(key: String): JsonPrimitive {
    jsonObject[key].apply {
        shouldBeInstanceOf<JsonPrimitive>()
        return this
    }
}
