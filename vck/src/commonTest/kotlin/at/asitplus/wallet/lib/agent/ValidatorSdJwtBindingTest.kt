package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsHeader
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class ValidatorSdJwtBindingTest : FreeSpec({

    lateinit var key: KeyMaterial

    beforeEach {
        key = EphemeralKeyWithoutCert()
    }

    "with jwk" {
        val claim = ConfirmationClaim(jsonWebKey = key.jsonWebKey)
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, jsonWebKey = key.jsonWebKey)

        claim.matches(header) shouldBe true
    }

    "with jku and kid, because there are two keys" {
        val jku = "https://example.com/" + uuid4().toString()
        val kid = uuid4().toString()
        val claim = ConfirmationClaim(jsonWebKeySetUrl = jku, keyId = kid)
        val randomSecondKey = EphemeralKeyWithoutCert().jsonWebKey.copy(keyId = uuid4().toString())
        val keySet = JsonWebKeySet(listOf(key.jsonWebKey.copy(keyId = kid), randomSecondKey))
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, jsonWebKeySetUrl = jku)

        claim.matches(header) shouldBe true
    }

    "with jku, but without kid, because there is only one key" {
        val claim = ConfirmationClaim(jsonWebKeySetUrl = "https://example.com")
        val keySet = JsonWebKeySet(listOf(key.jsonWebKey))
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, jsonWebKey = key.jsonWebKey)

        claim.matches(header) shouldBe true
    }

})