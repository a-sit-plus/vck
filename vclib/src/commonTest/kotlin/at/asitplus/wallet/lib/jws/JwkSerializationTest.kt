@file:OptIn(ExperimentalUuidApi::class)

package at.asitplus.wallet.lib.jws
import at.asitplus.wallet.lib.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlin.uuid.ExperimentalUuidApi

class JwkSerializationTest : FreeSpec({

    "Serialization contains P-256 as curve name" {
        val curve = EcCurve.SECP_256_R_1
        val kid = uuid4()
        val jwk = JsonWebKey(
            type = JwkType.EC,
            curve = curve,
            keyId = kid
        )

        val serialized = jwk.serialize()

        serialized shouldContain """"${curve.jwkName}""""
        serialized shouldContain """"$kid""""
    }

    "Deserialization is correct" {
        val curve = EcCurve.SECP_256_R_1
        val kid = uuid4()
        val serialized = """{"kty": "EC", "crv": "${curve.jwkName}", "kid": "$kid"}"""

        val parsed = JsonWebKey.deserialize(serialized)

        parsed.shouldNotBeNull()
        parsed.curve shouldBe curve
        parsed.keyId shouldBe kid
    }

    "Deserialization with unknown curve is correct" {
        val kid = uuid4()
        val serialized = """{"kty": "EC", "crv": "P-111", "kid": "$kid"}"""

        val parsed = JsonWebKey.deserialize(serialized)

        parsed.shouldNotBeNull()
        parsed.curve shouldBe null
        parsed.keyId shouldBe kid
    }

})
