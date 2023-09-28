package at.asitplus.wallet.lib.data

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

class CredentialSubjectTest : FreeSpec({
    "Subclasses are correctly deserialized" {
        @Serializable
        class SpecializedCredentialTest(override val id: String, @SerialName("not-foo") val foo: String): CredentialSubject()
        val result = Json.decodeFromString<SpecializedCredentialTest>("{\"id\":\"Test\",\"not-foo\":\"bar\"}")
        result.id shouldBe "Test"
        result.foo shouldBe "bar"
    }
})
