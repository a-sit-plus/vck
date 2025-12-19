package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

private const val TEST_SYSTEM_NAME = "test-system-v1"

val ZkSystemSpecSerializerTest by testSuite {
    
    ZkSystemParamRegistry.register(
        TEST_SYSTEM_NAME,
        mapOf(
            "string_param" to String.serializer(),
            "int_param" to Int.serializer(),
            "long_param" to Long.serializer(),
            "bool_param" to Boolean.serializer(),
        )
    )

    "serialize and deserialize ZkSystemSpec with string param" {
        val input = ZkSystemSpec(
            zkSystemId = "test-id-123",
            system = TEST_SYSTEM_NAME,
            params = mapOf("string_param" to "hello world")
        )

        val serialized = coseCompliantSerializer.encodeToByteArray(input)
        val deserialized = coseCompliantSerializer.decodeFromByteArray<ZkSystemSpec>(serialized)

        deserialized shouldBe input
        deserialized.params["string_param"] shouldBe "hello world"
        deserialized.params["string_param"].shouldBeInstanceOf<String>()
    }

    "serialize and deserialize ZkSystemSpec with int param" {
        val input = ZkSystemSpec(
            zkSystemId = "test-id-456",
            system = TEST_SYSTEM_NAME,
            params = mapOf("int_param" to 42)
        )

        val serialized = coseCompliantSerializer.encodeToByteArray(input)
        val deserialized = coseCompliantSerializer.decodeFromByteArray<ZkSystemSpec>(serialized)

        deserialized shouldBe input
        deserialized.params["int_param"] shouldBe 42
        deserialized.params["int_param"].shouldBeInstanceOf<Int>()
    }

    "serialize and deserialize ZkSystemSpec with long param" {
        val input = ZkSystemSpec(
            zkSystemId = "test-id-789",
            system = TEST_SYSTEM_NAME,
            params = mapOf("long_param" to 9876543210L)
        )

        val serialized = coseCompliantSerializer.encodeToByteArray(input)
        val deserialized = coseCompliantSerializer.decodeFromByteArray<ZkSystemSpec>(serialized)

        deserialized shouldBe input
        deserialized.params["long_param"] shouldBe 9876543210L
        deserialized.params["long_param"].shouldBeInstanceOf<Long>()
    }

    "serialize and deserialize ZkSystemSpec with boolean param" {
        val input = ZkSystemSpec(
            zkSystemId = "test-id-bool",
            system = TEST_SYSTEM_NAME,
            params = mapOf("bool_param" to true)
        )

        val serialized = coseCompliantSerializer.encodeToByteArray(input)
        val deserialized = coseCompliantSerializer.decodeFromByteArray<ZkSystemSpec>(serialized)

        deserialized shouldBe input
        deserialized.params["bool_param"] shouldBe true
        deserialized.params["bool_param"].shouldBeInstanceOf<Boolean>()
    }

    "serialize and deserialize ZkSystemSpec with multiple params" {
        val input = ZkSystemSpec(
            zkSystemId = "test-id-multi",
            system = TEST_SYSTEM_NAME,
            params = mapOf(
                "string_param" to "test string",
                "int_param" to 123,
                "long_param" to 999999999999L,
                "bool_param" to false
            )
        )

        val serialized = coseCompliantSerializer.encodeToByteArray(input)
        val deserialized = coseCompliantSerializer.decodeFromByteArray<ZkSystemSpec>(serialized)

        deserialized shouldBe input
        deserialized.params["string_param"] shouldBe "test string"
        deserialized.params["int_param"] shouldBe 123
        deserialized.params["long_param"] shouldBe 999999999999L
        deserialized.params["bool_param"] shouldBe false
    }

    "serialize and deserialize ZkSystemSpec with empty params" {
        val input = ZkSystemSpec(
            zkSystemId = "test-id-empty",
            system = TEST_SYSTEM_NAME,
            params = emptyMap()
        )

        val serialized = coseCompliantSerializer.encodeToByteArray(input)
        val deserialized = coseCompliantSerializer.decodeFromByteArray<ZkSystemSpec>(serialized)

        deserialized shouldBe input
        deserialized.params shouldBe emptyMap()
    }

    "serialize and deserialize ZkSystemSpec with unregistered system falls back to string" {
        val unregisteredSystem = "unregistered-system"
        val input = ZkSystemSpec(
            zkSystemId = "test-id-unregistered",
            system = unregisteredSystem,
            params = mapOf("unknown_param" to "some value")
        )

        val serialized = coseCompliantSerializer.encodeToByteArray(input)
        val deserialized = coseCompliantSerializer.decodeFromByteArray<ZkSystemSpec>(serialized)

        deserialized.zkSystemId shouldBe input.zkSystemId
        deserialized.system shouldBe input.system
        // Fallback decodes as string
        deserialized.params["unknown_param"] shouldBe "some value"
    }

    "getParam returns typed value" {
        val spec = ZkSystemSpec(
            zkSystemId = "test",
            system = TEST_SYSTEM_NAME,
            params = mapOf(
                "string_param" to "hello",
                "int_param" to 42
            )
        )

        spec.getParam<String>("string_param") shouldBe "hello"
        spec.getParam<Int>("int_param") shouldBe 42
        spec.getParam<String>("nonexistent") shouldBe null
        spec.getParam<Int>("string_param") shouldBe null // wrong type
    }

    "requireParam throws on missing param" {
        val spec = ZkSystemSpec(
            zkSystemId = "test",
            system = TEST_SYSTEM_NAME,
            params = mapOf("string_param" to "hello")
        )

        spec.requireParam<String>("string_param") shouldBe "hello"

        shouldThrow<IllegalStateException> {
            spec.requireParam<String>("nonexistent")
        }
    }
}

val ZkSystemParamRegistryTest by testSuite {

    "register and lookup serializer" {
        val testSystem = "registry-test-system-lookup"
        ZkSystemParamRegistry.register(
            testSystem,
            mapOf("param1" to String.serializer())
        )

        ZkSystemParamRegistry.lookupSerializer(testSystem, "param1") shouldBe String.serializer()
        ZkSystemParamRegistry.lookupSerializer(testSystem, "nonexistent") shouldBe null
        ZkSystemParamRegistry.lookupSerializer("unknown-system", "param1") shouldBe null
    }

    "register multiple systems independently" {
        val testSystem1 = "registry-test-system-1"
        val testSystem2 = "registry-test-system-2"

        ZkSystemParamRegistry.register(
            testSystem1,
            mapOf("param_a" to String.serializer())
        )
        ZkSystemParamRegistry.register(
            testSystem2,
            mapOf("param_b" to Int.serializer())
        )

        ZkSystemParamRegistry.lookupSerializer(testSystem1, "param_a") shouldBe String.serializer()
        ZkSystemParamRegistry.lookupSerializer(testSystem1, "param_b") shouldBe null
        ZkSystemParamRegistry.lookupSerializer(testSystem2, "param_b") shouldBe Int.serializer()
        ZkSystemParamRegistry.lookupSerializer(testSystem2, "param_a") shouldBe null
    }

    "register same system twice with compatible serializers merges" {
        val system = "merge-test-system"

        ZkSystemParamRegistry.register(
            system,
            mapOf("param1" to String.serializer())
        )
        ZkSystemParamRegistry.register(
            system,
            mapOf("param2" to Int.serializer())
        )

        ZkSystemParamRegistry.lookupSerializer(system, "param1") shouldBe String.serializer()
        ZkSystemParamRegistry.lookupSerializer(system, "param2") shouldBe Int.serializer()
    }

    "register same system with conflicting serializers throws" {
        val system = "conflict-test-system"

        ZkSystemParamRegistry.register(
            system,
            mapOf("param1" to String.serializer())
        )

        shouldThrow<IllegalStateException> {
            ZkSystemParamRegistry.register(
                system,
                mapOf("param1" to Int.serializer()) // Conflict: same key, different type
            )
        }
    }

    "register same system with identical serializers is idempotent" {
        val system = "idempotent-test-system"

        ZkSystemParamRegistry.register(
            system,
            mapOf("param1" to String.serializer())
        )
        // Should not throw - same registration
        ZkSystemParamRegistry.register(
            system,
            mapOf("param1" to String.serializer())
        )

        ZkSystemParamRegistry.lookupSerializer(system, "param1") shouldBe String.serializer()
    }

    "register same system with compatible serializers is idempotent" {
        val system = "idempotent-test-system"

        ZkSystemParamRegistry.register(
            system,
            mapOf(
                "param1" to String.serializer(),
                "param2" to Int.serializer(),
            )
        )
        // Should not throw - same registration
        ZkSystemParamRegistry.register(
            system,
            mapOf(
                "param1" to String.serializer(),
                "param3" to Long.serializer(),
            )
        )

        ZkSystemParamRegistry.lookupSerializer(system, "param1") shouldBe String.serializer()
        ZkSystemParamRegistry.lookupSerializer(system, "param2") shouldBe Int.serializer()
        ZkSystemParamRegistry.lookupSerializer(system, "param3") shouldBe Long.serializer()
    }
}

inline fun <reified T> ZkSystemSpec.getParam(key: String): T? = params[key] as? T

inline fun<reified T> ZkSystemSpec.requireParam(key: String): T = getParam<T>(key)
    ?: error("Required param '$key' not found or has wrong type in ZkSystemSpec")