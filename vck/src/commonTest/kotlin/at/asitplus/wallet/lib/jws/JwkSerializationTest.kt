package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwkType
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

val JwkSerializationTest by testSuite {

    "Serialization contains P-256 as curve name" {
        val curve = ECCurve.SECP_256_R_1
        val kid = uuid4().toString()
        val jwk = JsonWebKey(
            type = JwkType.EC,
            curve = curve,
            keyId = kid
        )

        val serialized = joseCompliantSerializer.encodeToString(jwk)

        serialized shouldContain """"${curve.jwkName}""""
        serialized shouldContain """"$kid""""
    }

    "Deserialization is correct" {
        val curve = ECCurve.SECP_256_R_1
        val kid = uuid4().toString()
        val serialized = """{"kty": "EC", "crv": "${curve.jwkName}", "kid": "$kid"}"""

        val parsed = joseCompliantSerializer.decodeFromString<JsonWebKey>(serialized)

        parsed.type shouldBe JwkType.EC
        parsed.curve shouldBe curve
        parsed.keyId shouldBe kid
    }

    "Deserialization with unknown curve does not fail, but sets it to null" {
        val kid = uuid4().toString()
        val serialized = """{"kty": "EC", "crv": "P-111", "kid": "$kid"}"""

        val parsed = joseCompliantSerializer.decodeFromString<JsonWebKey>(serialized)

        parsed.type shouldBe JwkType.EC
        parsed.curve.shouldBeNull()
        parsed.keyId shouldBe kid
    }

}
