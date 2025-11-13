package at.asitplus.wallet.lib.oidvci

import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

class OAuth2SecurityExtensionsClockTest : FunSpec({

    val keyMaterial = EphemeralKeyWithoutCert()
    val signJwt = SignJwt<JsonWebToken>(keyMaterial, JwsHeaderNone())
    val fixedInstant = Instant.fromEpochMilliseconds(1_726_358_400_000)
    val clock = object : Clock {
        override fun now(): Instant = fixedInstant
    }

    test("client attestation JWT honors provided clock") {
        val lifetime = 60.minutes
        val clockSkew = 5.minutes

        val signed = BuildClientAttestationJwt(
            signJwt = signJwt,
            clientId = "client-id",
            issuer = "issuer",
            clientKey = keyMaterial.jsonWebKey,
            lifetime = lifetime,
            clockSkew = clockSkew,
            clock = clock,
        )

        val payload = signed.payload
        payload.issuedAt shouldBe fixedInstant - clockSkew
        payload.expiration shouldBe fixedInstant - clockSkew + lifetime
        payload.confirmationClaim.shouldNotBeNull()
    }

    test("client attestation PoP JWT honors provided clock") {
        val lifetime = 10.minutes
        val clockSkew = 2.minutes

        val signed = BuildClientAttestationPoPJwt(
            signJwt = signJwt,
            clientId = "client-id",
            audience = "https://authorization.server",
            lifetime = lifetime,
            clockSkew = clockSkew,
            randomSource = RandomSource.Secure,
            clock = clock,
        )

        val payload = signed.payload
        payload.issuedAt shouldBe fixedInstant - clockSkew
        payload.expiration shouldBe fixedInstant - clockSkew + lifetime
        payload.jwtId.shouldNotBeNull()
    }
})

