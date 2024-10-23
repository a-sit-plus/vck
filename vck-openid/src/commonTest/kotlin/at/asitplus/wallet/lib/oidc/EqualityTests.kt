package at.asitplus.wallet.lib.oidc

import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.wallet.lib.Initializer.initOpenIdModule
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.booleans.shouldBeTrue
import kotlinx.serialization.SerialName
import kotlin.random.Random

class EqualityTests : FreeSpec({
    initOpenIdModule()
    lateinit var jwk1: JsonWebKey
    lateinit var jwk2: JsonWebKey

    beforeEach {
        jwk1 = JsonWebKey(x = Random.Default.nextBytes(32))
        jwk2 = JsonWebKey(x = Random.Default.nextBytes(32))
    }

    "JsonWebKeySet new" {
        val first = JsonWebKeySet(keys = listOf(jwk1, jwk2))
        val second = JsonWebKeySet(keys = listOf(jwk1, jwk2))

        val equals = first == second

        equals.shouldBeTrue()
    }

    "JsonWebKeySet new unordered" {
        val first = JsonWebKeySet(keys = setOf(jwk1, jwk2))
        val second = JsonWebKeySet(keys = setOf(jwk2, jwk1))

        val equals = first == second

        equals.shouldBeTrue()
    }

    "JsonWebKeySet old" {
        val first = OldJsonWebKeySet(keys = arrayOf(jwk1, jwk2))
        val second = OldJsonWebKeySet(keys = arrayOf(jwk1, jwk2))

        val equals = first == second

        equals.shouldBeTrue()
    }

    "JsonWebKeySet old unordered" {
        val first = OldJsonWebKeySet(keys = arrayOf(jwk1, jwk2))
        val second = OldJsonWebKeySet(keys = arrayOf(jwk1, jwk2).reversedArray())

        val equals = first == second

        // this is false, because the order matters on arrays
        //equals.shouldBeTrue()
    }
})

data class OldJsonWebKeySet(
    @SerialName("keys")
    val keys: Array<JsonWebKey>,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as OldJsonWebKeySet

        return keys.contentEquals(other.keys)
    }

    override fun hashCode(): Int {
        return keys.contentHashCode()
    }
}