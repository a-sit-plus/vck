package at.asitplus.wallet.lib.utils

import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.nulls.shouldBeNull
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.milliseconds

val DefaultMapStoreTest by testSuite {

    test("simple types are working") {
        with(
            DefaultMapStore<String, String>(
                lifetime = 20.milliseconds,
                sizeToCheckForExpiration = 1U
            )
        ) {
            val key = uuid4().toString()
            get(key).shouldBeNull()
            put(key, "value")
            delay(50.milliseconds)
            get(key).shouldBeNull()
        }
    }

    test("key array type is prevented") {
        with(
            DefaultMapStore<Array<String>, String>()
        ) {
            shouldThrowAny {
                put(arrayOf("key"), "value")
            }
        }
    }

    test("value array type is prevented") {
        with(
            DefaultMapStore<String, Array<String>>()
        ) {
            shouldThrowAny {
                put("key", arrayOf("value"))
            }
        }
    }
}