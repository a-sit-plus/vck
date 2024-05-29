package at.asitplus.wallet.lib.jws

import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.crypto.datatypes.jws.JwkType
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

class JwkSerializationTest : FreeSpec({

    "Serialization contains P-256 as curve name" {
        val curve = ECCurve.SECP_256_R_1
        val kid = uuid4().toString()
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
        val curve = ECCurve.SECP_256_R_1
        val kid = uuid4().toString()
        val serialized = """{"kty": "EC", "crv": "${curve.jwkName}", "kid": "$kid"}"""

        val parsed = JsonWebKey.deserialize(serialized).getOrThrow()

        parsed.curve shouldBe curve
        parsed.keyId shouldBe kid
    }

    "Deserialization with unknown curve fails" {
        val kid = uuid4().toString()
        val serialized = """{"kty": "EC", "crv": "P-111", "kid": "$kid"}"""

        val parsed = JsonWebKey.deserialize(serialized).getOrNull()

        parsed.shouldBeNull()
    }

})
