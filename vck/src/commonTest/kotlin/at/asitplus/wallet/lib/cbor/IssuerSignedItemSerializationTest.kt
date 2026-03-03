package at.asitplus.wallet.lib.cbor

import at.asitplus.iso.CborCredentialSerializer
import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceKeyInfo
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.IssuerSignedItemSerializer
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.ValidityInfo
import at.asitplus.iso.ValueDigest
import at.asitplus.iso.ValueDigestList
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseEllipticCurve
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.CoseKeyParams
import at.asitplus.signum.indispensable.cosef.CoseKeyType
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.withFixtureGenerator
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.LocalDate
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.decodeFromHexString
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encodeToHexString
import kotlin.random.Random
import kotlin.random.nextUInt
import kotlin.time.Clock
import kotlin.time.Instant

@OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)
val IssuerSignedItemSerializationTest by testSuite {

    withFixtureGenerator {
        object {
            val namespace = uuid4().toString()
            val elementId = uuid4().toString()
        }
    } - {

        test("serialization with String") {
            val item = IssuerSignedItem(
                digestId = Random.nextUInt(),
                random = Random.nextBytes(16),
                elementIdentifier = it.elementId,
                elementValue = uuid4().toString(),
            )
            coseCompliantSerializer.encodeToHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), item)
                .uppercase()
                .shouldNotContain("d903ec")

            // direct deserialization prevented, use in IssuerSignedList
        }

        test("serialization with Instant") {
            CborCredentialSerializer.register(mapOf(it.elementId to Instant.serializer()), it.namespace)
            val item = IssuerSignedItem(
                digestId = Random.nextUInt(),
                random = Random.nextBytes(16),
                elementIdentifier = it.elementId,
                elementValue = Clock.System.now(),
            )

            coseCompliantSerializer.encodeToHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), item)
                .shouldContain(
                    "elementValue".toHex()
                            + "c0" // tag(0)
                            + "78" // text(..)
                )

            // direct deserialization prevented, use in IssuerSignedList
        }

        test("serialization with LocalDate") {
            CborCredentialSerializer.register(mapOf(it.elementId to LocalDate.serializer()), it.namespace)
            val item = IssuerSignedItem(
                digestId = Random.nextUInt(),
                random = Random.nextBytes(16),
                elementIdentifier = it.elementId,
                elementValue = LocalDate.fromEpochDays(Random.nextInt(32768))
            )

            coseCompliantSerializer.encodeToHexString(IssuerSignedItemSerializer(it.namespace, it.elementId), item)
                .shouldContain(
                    "elementValue".toHex()
                            + "d903ec" // tag(1004)
                            + "6a" // text(10)
                )

            // direct deserialization prevented, use in IssuerSignedList
        }
    }
}

private fun String.toHex(): String = encodeToByteArray().encodeToString(Base16()).lowercase()
