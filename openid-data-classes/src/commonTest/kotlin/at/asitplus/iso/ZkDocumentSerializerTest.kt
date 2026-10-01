package at.asitplus.iso

import at.asitplus.csc.contentEquals
import at.asitplus.iso.ZkDocumentData.Companion.PROP_CERT_CHAIN
import at.asitplus.iso.ZkDocumentData.Companion.PROP_DOC_TYPE
import at.asitplus.iso.ZkDocumentData.Companion.PROP_TIME_STAMP
import at.asitplus.iso.ZkDocumentData.Companion.PROP_ZK_DEVICE_SIGNED
import at.asitplus.iso.ZkDocumentData.Companion.PROP_ZK_ISSUER_SIGNED
import at.asitplus.iso.ZkDocumentData.Companion.PROP_ZK_SYSTEM_ID
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.equals.shouldBeEqual
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Contextual
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.encodeToByteArray
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Instant

val ZkDocumentSerializationTest by matrixSuite {
    fixture {
        // Define and register namespaces used for issuer- and deviceSigned (with predefined values).
        // In production this should be done via import `LibraryInitializer` instead.
        val namespacesWithValues = listOf(
            uuid4().toString() to listOf<Triple<String, @Serializable Any, KSerializer<*>>>(
                Triple(uuid4().toString(), uuid4().toString(), String.serializer()),
                Triple(uuid4().toString(), Random.nextInt(0, 1001), Int.serializer()),
                Triple(uuid4().toString(), Clock.System.now().truncateToSeconds(), Instant.serializer()),
            ),
            uuid4().toString() to listOf<Triple<String, @Serializable Any, KSerializer<*>>>(
                Triple(uuid4().toString(), uuid4().toString(), String.serializer()),
            ),
            uuid4().toString() to listOf<Triple<String, @Serializable Any, KSerializer<*>>>(
                Triple(uuid4().toString(), uuid4().toString(), String.serializer()),
                Triple(uuid4().toString(), Random.nextDouble(0.0, 1337.327), Double.serializer()),
            ),
        )
        namespacesWithValues.forEach { (namespace, elementIdentifiersAndValuesAndSerializers) ->
            CborCredentialSerializer.register(
                serializerMap = elementIdentifiersAndValuesAndSerializers.associate { (identifier, _, serializer) -> identifier to serializer },
                isoNamespace = namespace
            )
        }

        object {
            val docType = uuid4().toString()
            val zkSystemId = uuid4().toString()
            val timestamp = Clock.System.now().truncateToSeconds()
            val issuerSigned = namespacesWithValues.take(2).associate {
                val (namespace, elementIdentifiersAndSerializers) = it
                namespace to ZkSignedList(
                    elementIdentifiersAndSerializers.map { (identifier, value, serializer) ->
                        ZkSignedItem(identifier, value)
                    }
                )
            }
            val deviceSigned = namespacesWithValues.takeLast(1).associate {
                val (namespace, elementIdentifiersAndSerializers) = it
                namespace to ZkSignedList(
                    elementIdentifiersAndSerializers.map { (identifier, value, serializer) ->
                        ZkSignedItem(identifier, value)
                    }
                )
            }
            val proof = uuid4().toString().encodeToByteArray()
            val testCert1 = uuid4().toString().encodeToByteArray()
            val testCert2 = uuid4().toString().encodeToByteArray()

            val baseZkDocumentData = ZkDocumentData(
                docType = docType,
                zkSystemId = zkSystemId,
                timestamp = timestamp,
                issuerSigned = issuerSigned,
                deviceSigned = deviceSigned,
            )

            fun getZkDocumentWithCertChain(vararg certs: ByteArray): ZkDocument = ZkDocument(
                zkDocumentDataBytes = ByteStringWrapper(
                    baseZkDocumentData.copy(
                        certificateChain = if (certs.isEmpty()) null else certs.toList()
                    )
                ),
                proof = proof
            )


        }
    } - {
        "End-to-end serialization and deserialization of ZkDocument" {
            val zkDoc = it.getZkDocumentWithCertChain(it.testCert1)
            val serialized = coseCompliantSerializer.encodeToByteArray(zkDoc)
            val deserialized = coseCompliantSerializer.decodeFromByteArray(ZkDocument.serializer(), serialized)
            zkDoc shouldBeEqual deserialized
        }

        "Serialization of ZkDocument with single cert according RFC9360" {
            val zkDoc = it.getZkDocumentWithCertChain(it.testCert1)
            val expectedData = zkDoc.zkDocumentDataBytes.value
            val serialized = coseCompliantSerializer.encodeToByteArray(zkDoc)

            // Sanity check: Implementation's serialization and deserialization produces expected ZkDocument
            // The serializer MUST serialize msoX5chain (in zkDocumentData) as bstr due to RFC9360,
            // because it only contains 1 certificate
            val deserializedDefault = coseCompliantSerializer.decodeFromByteArray(ZkDocument.serializer(), serialized)
            deserializedDefault shouldBeEqual zkDoc
            deserializedDefault.zkDocumentDataBytes.value.certificateChain!!.size shouldBe 1

            // Implementation's serializer correctly serializes ZkDocument in such a way that msoX5Chain is stored as a bstr
            // This is tested using a mock data class that comes with a simple deserializer which is only compatible with a
            // single certificate encoded as bstr.
            val deserializedMock = coseCompliantSerializer.decodeFromByteArray(MockZkDocumentSingleCert.serializer(), serialized)
            deserializedMock.proof.contentEquals(zkDoc.proof) shouldBe true
            val singleCertData = deserializedMock.zkDocumentDataBytes.value
            singleCertData.docType shouldBe expectedData.docType
            singleCertData.zkSystemId shouldBe expectedData.zkSystemId
            singleCertData.timestamp shouldBe expectedData.timestamp
            singleCertData.issuerSigned shouldBe expectedData.issuerSigned
            singleCertData.deviceSigned shouldBe expectedData.deviceSigned
            singleCertData.certificateChain.contentEquals(expectedData.certificateChain!!.single()) shouldBe true

            // Sanity check: Serialized ZkDocument with msoX5Chain encoded as bstr MUST NOT be deserializable into a simple
            // mock data class whose deserializer expects a certificate chain in the form of an Array of bstr.
            shouldThrowAny {
                coseCompliantSerializer.decodeFromByteArray(MockZkDocumentMultipleCerts.serializer(), serialized)
            }

        }

        "Serialization of ZkDocument with multiple certs according RFC9360" {
            val zkDoc = it.getZkDocumentWithCertChain(it.testCert1, it.testCert2)
            val expectedData = zkDoc.zkDocumentDataBytes.value
            val serialized = coseCompliantSerializer.encodeToByteArray(zkDoc)

            // Sanity check: Implementation's serialization and deserialization produces expected ZkDocument
            // The serializer MUST serialize msoX5chain (in zkDocumentData) as Array of bstr due to RFC9360,
            // because it contains more than 1 certificate in its chain
            val deserializedDefault = coseCompliantSerializer.decodeFromByteArray(ZkDocument.serializer(), serialized)
            deserializedDefault shouldBeEqual zkDoc
            deserializedDefault.zkDocumentDataBytes.value.certificateChain!!.size shouldBeGreaterThan 1

            // Implementation's serializer correctly serializes ZkDocument in such a way that msoX5Chain is stored as an
            // Array of bstr. This is tested using a mock data class that comes with a simple deserializer is only
            // compatible with certificates encoded as Array of bstr.
            val deserializedMock = coseCompliantSerializer.decodeFromByteArray(MockZkDocumentMultipleCerts.serializer(), serialized)
            deserializedMock.proof.contentEquals(zkDoc.proof) shouldBe true
            val multiCertData = deserializedMock.zkDocumentDataBytes.value
            multiCertData.docType shouldBe expectedData.docType
            multiCertData.zkSystemId shouldBe expectedData.zkSystemId
            multiCertData.timestamp shouldBe expectedData.timestamp
            multiCertData.issuerSigned shouldBe expectedData.issuerSigned
            multiCertData.deviceSigned shouldBe expectedData.deviceSigned
            multiCertData.certificateChain.contentEquals(expectedData.certificateChain) shouldBe true
            multiCertData.certificateChain!!.size shouldBeGreaterThan 1

            // Sanity check: Serialized ZkDocument with msoX5Chain encoded as Array of bstr MUST NOT be deserializable into
            // a simple mock data class whose deserializer expects a single certificate in the form of a bstr.
            shouldThrowAny {
                coseCompliantSerializer.decodeFromByteArray(MockZkDocumentSingleCert.serializer(), serialized)
            }
        }


        "Deserialize ZkDocument with single cert according to RFC 9360" {
            val mockDoc = MockZkDocumentSingleCert(
                proof = it.proof,
                zkDocumentDataBytes = ByteStringWrapper(
                    MockZkDocumentDataSingleCert(
                        docType = it.docType,
                        zkSystemId = it.zkSystemId,
                        timestamp = it.timestamp,
                        issuerSigned = it.issuerSigned,
                        deviceSigned = it.deviceSigned,
                        certificateChain = it.testCert1
                    )
                )
            )
            // Serialize a simple Mock Document with only one certificate with its simple default serializer to produce a
            // valid serialized ZKDocument with only one certificate encoded as bstr in its msoX5Chain.
            // Sanity check: Mock serialization and deserialization work correctly.
            val serialized = coseCompliantSerializer.encodeToByteArray(mockDoc)
            val deserializedMock = coseCompliantSerializer.decodeFromByteArray(MockZkDocumentSingleCert.serializer(), serialized)
            deserializedMock shouldBe mockDoc

            // Verify the implementation's deserializer handles single-cert representation correctly
            val expectedData = mockDoc.zkDocumentDataBytes.value
            val deserializedDefault = coseCompliantSerializer.decodeFromByteArray(ZkDocument.serializer(), serialized)
            deserializedDefault.proof.contentEquals(mockDoc.proof) shouldBe true
            val defaultData = deserializedDefault.zkDocumentDataBytes.value
            defaultData.docType shouldBe expectedData.docType
            defaultData.zkSystemId shouldBe expectedData.zkSystemId
            defaultData.timestamp shouldBe expectedData.timestamp
            defaultData.issuerSigned shouldBe expectedData.issuerSigned
            defaultData.deviceSigned shouldBe expectedData.deviceSigned
            defaultData.certificateChain!!.single().contentEquals(expectedData.certificateChain) shouldBe true

            // Sanity check: Serialized ZkDocument with msoX5Chain encoded as bstr MUST NOT be deserializable into a simple
            // Mock-ZkDocument whose deserializer expects an Array of bstr.
            shouldThrowAny {
                coseCompliantSerializer.decodeFromByteArray(MockZkDocumentMultipleCerts.serializer(), serialized)
            }
        }

        "Deserialize ZkDocument with multiple certs according to RFC 9360" {
            val mockDoc = MockZkDocumentMultipleCerts(
                proof = it.proof,
                zkDocumentDataBytes = ByteStringWrapper(
                    MockZkDocumentDataMultipleCerts(
                        docType = it.docType,
                        zkSystemId = it.zkSystemId,
                        timestamp = it.timestamp,
                        issuerSigned = it.issuerSigned,
                        deviceSigned = it.deviceSigned,
                        certificateChain = listOf(it.testCert1, it.testCert2)
                    )
                )
            )

            // Serialize a simple Mock Document with more than one certificate with its simple default serializer to produce
            // a valid serialized ZKDocument with multiple certificates encoded as Array of bstr in its msoX5Chain.
            // Sanity check: Mock serialization and deserialization work correctly.
            val serialized = coseCompliantSerializer.encodeToByteArray(mockDoc)
            val deserializedMock = coseCompliantSerializer.decodeFromByteArray(MockZkDocumentMultipleCerts.serializer(), serialized)
            deserializedMock shouldBe mockDoc

            // Verify the implementation's deserializer handles multi-cert representation correctly
            val expectedData = mockDoc.zkDocumentDataBytes.value
            val deserializedDefault = coseCompliantSerializer.decodeFromByteArray(ZkDocument.serializer(), serialized)
            deserializedDefault.proof.contentEquals(mockDoc.proof) shouldBe true
            val defaultData = deserializedDefault.zkDocumentDataBytes.value
            defaultData.docType shouldBe expectedData.docType
            defaultData.zkSystemId shouldBe expectedData.zkSystemId
            defaultData.timestamp shouldBe expectedData.timestamp
            defaultData.issuerSigned shouldBe expectedData.issuerSigned
            defaultData.deviceSigned shouldBe expectedData.deviceSigned
            defaultData.certificateChain.contentEquals(expectedData.certificateChain) shouldBe true
            defaultData.certificateChain!!.size shouldBeGreaterThan 1

            // Sanity check: Serialized ZkDocument with msoX5Chain encoded as array of bstr MUST NOT be deserializable into
            // a simple Mock-ZkDocument whose deserializer expects a single bstr.
            shouldThrowAny {
                coseCompliantSerializer.decodeFromByteArray(MockZkDocumentSingleCert.serializer(), serialized)
            }
        }

        "Serialization and deserialization of ZkDocument without cert" {
            val zkDoc = it.getZkDocumentWithCertChain(/* No certificate */)
            val serialized = coseCompliantSerializer.encodeToByteArray(zkDoc)
            val deserializedDefault = coseCompliantSerializer.decodeFromByteArray(ZkDocument.serializer(), serialized)
            deserializedDefault shouldBeEqual zkDoc
            deserializedDefault.zkDocumentDataBytes.value.certificateChain shouldBe null
        }
    }

}
@Serializable
private data class MockZkDocumentSingleCert(
    @SerialName("documentData")
    @ValueTags(24u)
    val zkDocumentDataBytes: ByteStringWrapper<MockZkDocumentDataSingleCert>,
    @SerialName("proof")
    @ByteString
    val proof: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MockZkDocumentSingleCert) return false
        if (zkDocumentDataBytes != other.zkDocumentDataBytes) return false
        if (!proof.contentEquals(other.proof)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = zkDocumentDataBytes.hashCode()
        result = 31 * result + proof.contentHashCode()
        return result
    }
}

@Serializable
private data class MockZkDocumentMultipleCerts(
    @SerialName("documentData")
    @ValueTags(24u)
    val zkDocumentDataBytes: ByteStringWrapper<MockZkDocumentDataMultipleCerts>,
    @SerialName("proof")
    @ByteString
    val proof: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MockZkDocumentMultipleCerts) return false
        if (zkDocumentDataBytes != other.zkDocumentDataBytes) return false
        if (!proof.contentEquals(other.proof)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = zkDocumentDataBytes.hashCode()
        result = 31 * result + proof.contentHashCode()
        return result
    }
}

@Serializable
private data class MockZkDocumentDataSingleCert(
    @SerialName(PROP_DOC_TYPE)
    val docType: String,
    @SerialName(PROP_ZK_SYSTEM_ID)
    val zkSystemId: String,
    @SerialName(PROP_TIME_STAMP)
    @ValueTags(0u)
    val timestamp: Instant,
    @SerialName(PROP_ZK_ISSUER_SIGNED)
    @Serializable(with = NamespacedZkSignedListSerializer::class)
    val issuerSigned: Map<String, @Contextual ZkSignedList>? = null,
    @SerialName(PROP_ZK_DEVICE_SIGNED)
    @Serializable(with = NamespacedZkSignedListSerializer::class)
    val deviceSigned: Map<String, @Contextual ZkSignedList>? = null,
    @SerialName(PROP_CERT_CHAIN)
    @Serializable
    val certificateChain: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MockZkDocumentDataSingleCert) return false

        if (docType != other.docType) return false
        if (zkSystemId != other.zkSystemId) return false
        if (timestamp != other.timestamp) return false
        if (issuerSigned != other.issuerSigned) return false
        if (deviceSigned != other.deviceSigned) return false
        if (!certificateChain.contentEquals(other.certificateChain)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = docType.hashCode()
        result = 31 * result + zkSystemId.hashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + issuerSigned.hashCode()
        result = 31 * result + deviceSigned.hashCode()
        result = 31 * result + (certificateChain?.contentHashCode() ?: 0)
        return result
    }
}

@Serializable
private data class MockZkDocumentDataMultipleCerts(
    @SerialName(PROP_DOC_TYPE)
    val docType: String,
    @SerialName(PROP_ZK_SYSTEM_ID)
    val zkSystemId: String,
    @SerialName(PROP_TIME_STAMP)
    @ValueTags(0u)
    val timestamp: Instant,
    @SerialName(PROP_ZK_ISSUER_SIGNED)
    @Serializable(with = NamespacedZkSignedListSerializer::class)
    val issuerSigned: Map<String, @Contextual ZkSignedList>? = null,
    @SerialName(PROP_ZK_DEVICE_SIGNED)
    @Serializable(with = NamespacedZkSignedListSerializer::class)
    val deviceSigned: Map<String, @Contextual ZkSignedList>? = null,
    @SerialName(PROP_CERT_CHAIN)
    @Serializable(with = NormalizedX509Serializer::class)
    val certificateChain: List<ByteArray>? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MockZkDocumentDataMultipleCerts) return false

        if (docType != other.docType) return false
        if (zkSystemId != other.zkSystemId) return false
        if (timestamp != other.timestamp) return false
        if (issuerSigned != other.issuerSigned) return false
        if (deviceSigned != other.deviceSigned) return false

        if (certificateChain == null && other.certificateChain != null) return false
        if (certificateChain != null && other.certificateChain == null) return false
        if (certificateChain != null && other.certificateChain != null) {
            if (certificateChain.size != other.certificateChain.size) return false
            for (i in certificateChain.indices) {
                if (!certificateChain[i].contentEquals(other.certificateChain[i])) return false
            }
        }

        return true
    }

    override fun hashCode(): Int {
        var result = docType.hashCode()
        result = 31 * result + zkSystemId.hashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + issuerSigned.hashCode()
        result = 31 * result + deviceSigned.hashCode()
        result = 31 * result + (certificateChain?.sumOf { it.contentHashCode() } ?: 0)
        return result
    }
}
