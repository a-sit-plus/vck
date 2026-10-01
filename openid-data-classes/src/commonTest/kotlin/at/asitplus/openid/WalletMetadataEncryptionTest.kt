package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JwkType
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

/**
 * Wallet metadata parameters for encrypted authorization requests, as per
 * [OpenID4VP 1.0, 5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request-uri-method-post).
 */
val WalletMetadataEncryptionTest by matrixSuite {

    test("serializes and parses back") {
        val metadata = OAuth2AuthorizationServerMetadata(
            issuer = "https://wallet.example.com",
            jsonWebKeySet = JsonWebKeySet(
                listOf(
                    JsonWebKey(
                        type = JwkType.EC,
                        keyId = "some-key-id",
                        algorithm = JweAlgorithm.ECDH_ES,
                        publicKeyUse = "enc",
                    )
                )
            ),
            requestObjectEncryptionAlgValuesSupportedStrings = setOf(JweAlgorithm.ECDH_ES.identifier),
            requestObjectEncryptionEncValuesSupportedStrings = setOf(
                JweEncryption.A128GCM.identifier,
                JweEncryption.A256GCM.identifier,
            ),
        )

        val serialized = joseCompliantSerializer.encodeToString(metadata)
        serialized shouldContain "\"jwks\""
        serialized shouldContain "\"request_object_encryption_alg_values_supported\""
        serialized shouldContain "\"request_object_encryption_enc_values_supported\""

        joseCompliantSerializer.decodeFromString<OAuth2AuthorizationServerMetadata>(serialized).apply {
            jsonWebKeySet.shouldNotBeNull().keys.first().keyId shouldBe "some-key-id"
            requestObjectEncryptionAlgValuesSupported shouldBe setOf(JweAlgorithm.ECDH_ES)
            requestObjectEncryptionEncValuesSupported shouldBe
                    setOf(JweEncryption.A128GCM, JweEncryption.A256GCM)
        }
    }

    test("unset parameters resolve to null") {
        OAuth2AuthorizationServerMetadata(issuer = "https://wallet.example.com").apply {
            jsonWebKeySet shouldBe null
            requestObjectEncryptionAlgValuesSupported shouldBe null
            requestObjectEncryptionEncValuesSupported shouldBe null
        }
    }

    test("unknown algorithms are dropped") {
        OAuth2AuthorizationServerMetadata(
            issuer = "https://wallet.example.com",
            requestObjectEncryptionAlgValuesSupportedStrings = setOf("NOT-AN-ALG"),
            requestObjectEncryptionEncValuesSupportedStrings = setOf("NOT-AN-ENC", JweEncryption.A128GCM.identifier),
        ).apply {
            requestObjectEncryptionAlgValuesSupported shouldBe emptySet()
            requestObjectEncryptionEncValuesSupported shouldBe setOf(JweEncryption.A128GCM)
        }
    }
}
