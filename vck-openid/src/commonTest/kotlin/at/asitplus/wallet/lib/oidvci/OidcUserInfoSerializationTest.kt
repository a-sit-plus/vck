package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.wallet.lib.Initializer.initOpenIdModule
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonPrimitive

class OidcUserInfoSerializationTest : FunSpec({
    initOpenIdModule()
    test("Basic") {
        val input = """
        {
            "sub": "testvalue-sub",
            "name": "testvalue-name"
        }
        """.trimIndent()

        val deserialized = OidcUserInfoExtended.deserialize(input).getOrThrow()

        deserialized.userInfo.subject shouldBe "testvalue-sub"
        deserialized.userInfo.name shouldBe "testvalue-name"
        assertKeyHasValue(deserialized, "sub", "testvalue-sub")
        assertKeyHasValue(deserialized, "name", "testvalue-name")
    }

    test("Extended attributes") {
        val input = """
        {
            "sub": "testvalue-sub",
            "name": "testvalue-name",
            "foo": "testvalue-foo"
        }
        """.trimIndent()

        val deserialized = OidcUserInfoExtended.deserialize(input).getOrThrow()

        deserialized.userInfo.subject shouldBe "testvalue-sub"
        deserialized.userInfo.name shouldBe "testvalue-name"
        assertKeyHasValue(deserialized, "sub", "testvalue-sub")
        assertKeyHasValue(deserialized, "name", "testvalue-name")
        assertKeyHasValue(deserialized, "foo", "testvalue-foo")
    }

})

private fun assertKeyHasValue(deserialized: OidcUserInfoExtended, key: String, value: String) {
    deserialized.jsonObject [key].apply {
        shouldBeInstanceOf<JsonPrimitive>()
        content shouldBe value
    }
}
