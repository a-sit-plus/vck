package at.asitplus.wallet.ios

import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val JwsCompactCodecTest by matrixSuite {

    val codec = JwsCompactCodec(JsonWebToken.serializer())

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

        val parsed = codec.decodeFromString(jwt.jws.toString())

        parsed.payload.issuer shouldBe "https://wallet-provider.example"
        parsed.payload.confirmationClaim?.jsonWebKey?.jwkThumbprint shouldBe key.jsonWebKey.jwkThumbprint
        codec.encodeToString(parsed) shouldBe jwt.jws.toString()
    }

    test("rejects malformed compact JWTs") {
        val malformed = "not-a-jwt"

        shouldThrow<IllegalArgumentException> { codec.decodeFromString(malformed) }
    }

    test("rejects payloads that are not JSON") {
        val notJson = "eyJhbGciOiJub25lIn0.bm90LWpzb24.AA" // {"alg":"none"}.not-json

        shouldThrow<IllegalArgumentException> { codec.decodeFromString(notJson) }
    }
}
