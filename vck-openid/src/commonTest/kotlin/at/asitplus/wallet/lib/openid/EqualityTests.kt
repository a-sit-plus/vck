package at.asitplus.wallet.lib.openid

import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.booleans.shouldBeTrue
import kotlinx.serialization.SerialName
import kotlin.random.Random

val EqualityTests by testSuite {
    withFixtureGenerator {
        object {
            val jwk1 = JsonWebKey(x = Random.Default.nextBytes(32))
            val jwk2 = JsonWebKey(x = Random.Default.nextBytes(32))
        }
    } - {

        "JsonWebKeySet new" { it ->
            val first = JsonWebKeySet(keys = listOf(it.jwk1, it.jwk2))
            val second = JsonWebKeySet(keys = listOf(it.jwk1, it.jwk2))

            val equals = first == second

            equals.shouldBeTrue()
        }

        "JsonWebKeySet new unordered" { it ->
            val first = JsonWebKeySet(keys = setOf(it.jwk1, it.jwk2))
            val second = JsonWebKeySet(keys = setOf(it.jwk2, it.jwk1))

            val equals = first == second

            equals.shouldBeTrue()
        }

        "JsonWebKeySet old" { it ->
            val first = OldJsonWebKeySet(keys = arrayOf(it.jwk1, it.jwk2))
            val second = OldJsonWebKeySet(keys = arrayOf(it.jwk1, it.jwk2))

            val equals = first == second

            equals.shouldBeTrue()
        }

        "JsonWebKeySet old unordered" { it ->
            val first = OldJsonWebKeySet(keys = arrayOf(it.jwk1, it.jwk2))
            val second = OldJsonWebKeySet(keys = arrayOf(it.jwk1, it.jwk2).reversedArray())

            val equals = first == second

            // this is false, because the order matters on arrays
            //equals.shouldBeTrue()
        }
    }
}

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

    override fun hashCode(): Int = keys.contentHashCode()
}