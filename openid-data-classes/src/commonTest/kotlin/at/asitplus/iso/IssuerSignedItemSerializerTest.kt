package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.withFixtureGenerator
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.LocalDate
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.decodeFromHexString
import kotlinx.serialization.encodeToHexString
import kotlin.random.Random
import kotlin.random.nextUInt
import kotlin.time.Clock
import kotlin.time.Instant

@OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)
val IssuerSignedItemSerializerTest by testSuite {

    withFixtureGenerator {
        object {
            val namespace = uuid4().toString()
            val elementId = uuid4().toString()
        }
    } - {

        test("serialization with String (unregistered)") {
            val item = IssuerSignedItem(
                digestId = Random.nextUInt(),
                random = Random.nextBytes(16),
                elementIdentifier = it.elementId,
                elementValue = uuid4().toString(),
            )
            val serialized = coseCompliantSerializer
                .encodeToHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), item)
                .uppercase()
                .shouldNotContain("d903ec")
                .shouldNotBeNull()

            coseCompliantSerializer
                .decodeFromHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), serialized)
                .shouldBe(item)
        }

        test("serialization with Long (unregistered)") {
            val item = IssuerSignedItem(
                digestId = Random.nextUInt(),
                random = Random.nextBytes(16),
                elementIdentifier = it.elementId,
                elementValue = Random.nextLong(),
            )
            val serialized = coseCompliantSerializer
                .encodeToHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), item)
                .uppercase()
                .shouldNotContain("d903ec")
                .shouldNotBeNull()

            coseCompliantSerializer
                .decodeFromHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), serialized)
                .shouldBe(item)
        }

        test("serialization with Boolean (unregistered)") {
            val item = IssuerSignedItem(
                digestId = Random.nextUInt(),
                random = Random.nextBytes(16),
                elementIdentifier = it.elementId,
                elementValue = Random.nextBoolean(),
            )
            val serialized = coseCompliantSerializer
                .encodeToHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), item)
                .uppercase()
                .shouldNotContain("d903ec")
                .shouldNotBeNull()

            coseCompliantSerializer
                .decodeFromHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), serialized)
                .shouldBe(item)
        }

        test("serialization with Instant (registered)") {
            CborCredentialSerializer.register(mapOf(it.elementId to Instant.serializer()), it.namespace)
            val item = IssuerSignedItem(
                digestId = Random.nextUInt(),
                random = Random.nextBytes(16),
                elementIdentifier = it.elementId,
                elementValue = Clock.System.now(),
            )

            val serialized = coseCompliantSerializer
                .encodeToHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), item)
                .shouldContain(
                    //                     tag(0)  text(...)
                    "elementValue".toHex() + "c0" + "78"
                ).shouldNotBeNull()

            coseCompliantSerializer
                .decodeFromHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), serialized)
                .shouldBe(item)
        }

        test("serialization with Instant (unregistered) not working") {
            val item = IssuerSignedItem(
                digestId = Random.nextUInt(),
                random = Random.nextBytes(16),
                elementIdentifier = it.elementId,
                elementValue = Clock.System.now(),
            )

            val serialized = coseCompliantSerializer
                .encodeToHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), item)
                .shouldContain(
                    //                     tag(0)  text(...)
                    "elementValue".toHex() + "c0" + "78"
                ).shouldNotBeNull()

            val parsed = coseCompliantSerializer
                .decodeFromHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), serialized)

            shouldThrowAny {
                parsed.shouldBe(item)
            }
        }

        test("serialization with LocalDate (registered)") {
            CborCredentialSerializer.register(mapOf(it.elementId to LocalDate.serializer()), it.namespace)
            val item = IssuerSignedItem(
                digestId = Random.nextUInt(),
                random = Random.nextBytes(16),
                elementIdentifier = it.elementId,
                elementValue = LocalDate.fromEpochDays(Random.nextInt(32768))
            )

            val serialized = coseCompliantSerializer
                .encodeToHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), item)
                .shouldContain(
                    //                      tag(1004)  text(10)
                    "elementValue".toHex() + "d903ec" + "6a"
                ).shouldNotBeNull()

            coseCompliantSerializer
                .decodeFromHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), serialized)
                .shouldBe(item)
        }
    }
}

private fun String.toHex(): String = encodeToByteArray().encodeToString(Base16()).lowercase()
