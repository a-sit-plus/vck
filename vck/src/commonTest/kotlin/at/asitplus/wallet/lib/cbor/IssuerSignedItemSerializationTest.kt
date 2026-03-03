package at.asitplus.wallet.lib.cbor

import at.asitplus.iso.CborCredentialSerializer
import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceKeyInfo
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceResponse
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
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.data.LocalDateOrInstant
import at.asitplus.wallet.lib.data.LocalDateOrInstantSerializer
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.LocalDate
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
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
            val serialized =
                coseCompliantSerializer.encodeToByteArray(IssuerSignedItemSerializer(it.namespace, it.elementId), item)
            serialized.encodeToString(Base16()).shouldNotContain("D903EC")

            coseCompliantSerializer.decodeFromByteArray(
                IssuerSignedItemSerializer("", it.elementId),
                serialized
            ) shouldBe item
        }

        test("serialization with Instant") {
            CborCredentialSerializer.register(mapOf(it.elementId to Instant.serializer()), it.namespace)
            val item = IssuerSignedItem(
                digestId = Random.nextUInt(),
                random = Random.nextBytes(16),
                elementIdentifier = it.elementId,
                elementValue = Clock.System.now(),
            )

            val serialized =
                coseCompliantSerializer.encodeToByteArray(IssuerSignedItemSerializer(it.namespace, it.elementId), item)
                    .apply {
                        encodeToString(Base16()).shouldContain(
                            "elementValue".toHex()
                                    + "C0" // tag(0)
                                    + "78" // text(..)
                        )
                    }

            coseCompliantSerializer.decodeFromByteArray(
                IssuerSignedItemSerializer(it.namespace, it.elementId),
                serialized
            ) shouldBe item
        }

        test("serialization with LocalDate") {
            CborCredentialSerializer.register(mapOf(it.elementId to LocalDate.serializer()), it.namespace)
            val item = IssuerSignedItem(
                digestId = Random.nextUInt(),
                random = Random.nextBytes(16),
                elementIdentifier = it.elementId,
                elementValue = LocalDate.fromEpochDays(Random.nextInt(32768))
            )

            val serialized =
                coseCompliantSerializer.encodeToByteArray(IssuerSignedItemSerializer(it.namespace, it.elementId), item)
                    .apply {
                        encodeToString(Base16()).shouldContain(
                            "elementValue".toHex()
                                    + "D903EC" // tag(1004)
                                    + "6A" // text(10)
                        )
                    }

            coseCompliantSerializer.decodeFromByteArray(
                IssuerSignedItemSerializer(it.namespace, it.elementId),
                serialized
            ) shouldBe item
        }

        test("document serialization with ByteArray") {
            CborCredentialSerializer.register(mapOf(it.elementId to ByteArraySerializer()), it.namespace)
            val digestId = 13u
            val item = IssuerSignedItem(
                digestId = digestId,
                random = Random.nextBytes(16),
                elementIdentifier = it.elementId,
                elementValue = Random.nextBytes(32),
            )
            val protectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.RS256)
            val mso = MobileSecurityObject(
                version = "1.0",
                digestAlgorithm = "SHA-256",
                valueDigests = mapOf(
                    it.namespace to ValueDigestList(
                        listOf(ValueDigest.fromIssuerSignedItem(item, it.namespace))
                    )
                ),
                deviceKeyInfo = DeviceKeyInfo(
                    CoseKey(
                        CoseKeyType.EC2,
                        keyParams = CoseKeyParams.EcYBoolParams(CoseEllipticCurve.P256)
                    )
                ),
                docType = it.namespace,
                validityInfo = ValidityInfo(Clock.System.now(), Clock.System.now(), Clock.System.now()),
            )
            val issuerAuth = CoseSigned.create(
                protectedHeader,
                null,
                mso,
                CryptoSignature.RSA(byteArrayOf()),
                MobileSecurityObject.serializer()
            )
            val doc = Document(
                docType = uuid4().toString(),
                issuerSigned = IssuerSigned.fromIssuerSignedItems(
                    mapOf(it.namespace to listOf(item)),
                    issuerAuth
                ),
                deviceSigned = DeviceSigned(
                    ByteStringWrapper(DeviceNameSpaces(mapOf())),
                    DeviceAuth()
                )
            )
            val serialized = coseCompliantSerializer.encodeToByteArray(doc).apply {
                encodeToString(Base16()).apply {
                    shouldNotContain("D903EC")
                    val itemSerialized = coseCompliantSerializer.encodeToByteArray(
                        IssuerSignedItemSerializer(it.namespace, item.elementIdentifier), item
                    )
                    val itemBytes = coseCompliantSerializer.encodeToByteArray(ByteArraySerializer(), itemSerialized)
                    shouldContain( // inside the document
                        "nameSpaces".toHex()
                                + "A1" // map(1)
                                + "7824" // text(36)
                                + it.namespace.toHex()
                                + "81" // array(1)
                                + "D818" // tag(24)
                                + itemBytes.encodeToString(Base16())
                    )
                    // important here is wrapping in D818 before hashing it!
                    val itemHash = itemBytes.wrapInCborTag(24).sha256()
                    shouldContain( // inside the mso
                        it.namespace.toHex()
                                + "A1" // map(1)
                                + "0D" // unsigned 13, the digestId
                                + "5820" // bytes(32)
                                + itemHash.encodeToString(Base16())
                    )
                }
            }

            coseCompliantSerializer.decodeFromByteArray<Document>(serialized) shouldBe doc
        }

    }
}

private fun String.toHex(): String = encodeToByteArray().encodeToString(Base16())
