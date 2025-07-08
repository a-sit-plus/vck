package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

class JweSerializationTest : FreeSpec({

    "Serialization is correct" {
        val kid = uuid4()
        val algorithm = JweAlgorithm.ECDH_ES
        val encryption = JweEncryption.A256GCM
        val type = JwsContentType.JWT
        val jweHeader = JweHeader(
            algorithm = algorithm,
            encryption = encryption,
            keyId = kid,
            type = type,
        )

        val serialized = jweHeader.serialize()

        serialized shouldContain """"${algorithm.text}""""
        serialized shouldContain """"${encryption.text}""""
        serialized shouldContain """"$kid""""
        serialized shouldContain """"${type.text}""""
    }

    "Deserialization is correct" {
        val kid = uuid4()
        val algorithm = JweAlgorithm.ECDH_ES
        val encryption = JweEncryption.A256GCM
        val type = JwsContentType.JWT
        val serialized = """{"alg": "${algorithm.text}", "enc": "${encryption.text}", "kid": "$kid", "typ": "${type.text}"}"""

        val parsed = JweHeader.deserialize(serialized)

        parsed.shouldNotBeNull()
        parsed.algorithm shouldBe algorithm
        parsed.encryption shouldBe encryption
        parsed.keyId shouldBe kid
        parsed.type shouldBe type
    }

    "Deserialization with unknown algorithm is correct" {
        val kid = uuid4()
        val encryption = JweEncryption.A256GCM
        val type = JwsContentType.JWT
        val serialized = """{"alg": "foo", "enc": "${encryption.text}", "kid": "$kid", "typ": "${type.text}"}"""

        val parsed = JweHeader.deserialize(serialized)

        parsed.shouldNotBeNull()
        parsed.algorithm shouldBe null
        parsed.encryption shouldBe encryption
        parsed.keyId shouldBe kid
        parsed.type shouldBe type
    }

    "Deserialization with unknown encryption is correct" {
        val kid = uuid4()
        val algorithm = JweAlgorithm.ECDH_ES
        val type = JwsContentType.JWT
        val serialized = """{"alg": "${algorithm.text}", "enc": "foo", "kid": "$kid", "typ": "${type.text}"}"""

        val parsed = JweHeader.deserialize(serialized)

        parsed.shouldNotBeNull()
        parsed.algorithm shouldBe algorithm
        parsed.encryption shouldBe null
        parsed.keyId shouldBe kid
        parsed.type shouldBe type
    }

    "Deserialization with unknown type is correct" {
        val kid = uuid4()
        val algorithm = JweAlgorithm.ECDH_ES
        val encryption = JweEncryption.A256GCM
        val serialized = """{"alg": "${algorithm.text}", "enc": "${encryption.text}", "kid": "$kid", "typ": "foo"}"""

        val parsed = JweHeader.deserialize(serialized)

        parsed.shouldNotBeNull()
        parsed.algorithm shouldBe algorithm
        parsed.encryption shouldBe encryption
        parsed.keyId shouldBe kid
        parsed.type shouldBe null
    }

})
