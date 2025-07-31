package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

class JweSerializationTest : FreeSpec({

    "Serialization is correct" {
        val kid = uuid4().toString()
        val algorithm = JweAlgorithm.ECDH_ES
        val encryption = JweEncryption.A256GCM
        val type = JwsContentTypeConstants.JWT
        val jweHeader = JweHeader(
            algorithm = algorithm,
            encryption = encryption,
            keyId = kid,
            type = type,
        )

        val serialized = joseCompliantSerializer.encodeToString(jweHeader)

        serialized shouldContain """"${algorithm.identifier}""""
        serialized shouldContain """"${encryption.text}""""
        serialized shouldContain """"$kid""""
        serialized shouldContain """"$type""""
    }

    "Deserialization is correct" {
        val kid = uuid4().toString()
        val algorithm = JweAlgorithm.ECDH_ES
        val encryption = JweEncryption.A256GCM
        val type = JwsContentTypeConstants.JWT
        val serialized = """{"alg": "${algorithm.identifier}", "enc": "${encryption.text}", "kid": "$kid", "typ": "$type"}"""

        val parsed = joseCompliantSerializer.decodeFromString<JweHeader>(serialized)

        parsed.algorithm shouldBe algorithm
        parsed.encryption shouldBe encryption
        parsed.keyId shouldBe kid
        parsed.type shouldBe type
    }

    "Deserialization with unknown algorithm is correct" {
        val kid = uuid4().toString()
        val encryption = JweEncryption.A256GCM
        val type = JwsContentTypeConstants.JWT
        val serialized = """{"alg": "foo", "enc": "${encryption.text}", "kid": "$kid", "typ": "$type"}"""

        val parsed = joseCompliantSerializer.decodeFromString<JweHeader>(serialized)

        parsed.algorithm?.identifier shouldBe "foo"
        parsed.encryption shouldBe encryption
        parsed.keyId shouldBe kid
        parsed.type shouldBe type
    }

    "Deserialization with unknown encryption is correct" {
        val kid = uuid4().toString()
        val algorithm = JweAlgorithm.ECDH_ES
        val type = JwsContentTypeConstants.JWT
        val serialized = """{"alg": "${algorithm.identifier}", "enc": "foo", "kid": "$kid", "typ": "$type"}"""

        val parsed = joseCompliantSerializer.decodeFromString<JweHeader>(serialized)

        parsed.algorithm shouldBe algorithm
        parsed.encryption shouldBe null
        parsed.keyId shouldBe kid
        parsed.type shouldBe type
    }

    "Deserialization with unknown type is correct" {
        val kid = uuid4().toString()
        val algorithm = JweAlgorithm.ECDH_ES
        val encryption = JweEncryption.A256GCM
        val type = uuid4().toString()
        val serialized = """{"alg": "${algorithm.identifier}", "enc": "${encryption.text}", "kid": "$kid", "typ": "$type"}"""

        val parsed = joseCompliantSerializer.decodeFromString<JweHeader>(serialized)

        parsed.algorithm shouldBe algorithm
        parsed.encryption shouldBe encryption
        parsed.keyId shouldBe kid
        parsed.type shouldBe type
    }

})
