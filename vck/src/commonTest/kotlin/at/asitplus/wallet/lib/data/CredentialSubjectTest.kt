package at.asitplus.wallet.lib.data

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

val CredentialSubjectTest by testSuite {
    "Subclasses are correctly deserialized" {
        @Serializable
        class SpecializedCredentialTest(override val id: String, @SerialName("not-foo") val foo: String) :
            CredentialSubject()

        val result = Json.decodeFromString<SpecializedCredentialTest>("{\"id\":\"Test\",\"not-foo\":\"bar\"}")
        result.id shouldBe "Test"
        result.foo shouldBe "bar"
    }
}