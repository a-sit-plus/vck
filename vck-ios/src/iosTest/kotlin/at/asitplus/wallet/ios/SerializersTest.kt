package at.asitplus.wallet.ios

import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe

val SerializersTest by matrixSuite {

    test("parses a compact JWT with its payload") {
        val key = EphemeralKeyWithoutCert()
        val jwt = SignJwt<JsonWebToken>(key, JwsHeaderNone())(
            type = "oauth-client-attestation+jwt",
            payload = JsonWebToken(
                issuer = "https://wallet-provider.example",
                confirmationClaim = ConfirmationClaim(jsonWebKey = key.jsonWebKey),
            ),
            serializer = JsonWebToken.serializer(),
        ).getOrThrow()

        val parsed = VckSerializer.joseDeserializeJsonWebTokenJws(jwt.jws.toString())

        parsed.payload.issuer shouldBe "https://wallet-provider.example"
        parsed.payload.confirmationClaim?.jsonWebKey?.jwkThumbprint shouldBe key.jsonWebKey.jwkThumbprint
    }

    test("rejects malformed compact JWTs") {
        val malformed = "not-a-jwt"

        shouldThrowAny { VckSerializer.joseDeserializeJsonWebTokenJws(malformed) }
    }
}
