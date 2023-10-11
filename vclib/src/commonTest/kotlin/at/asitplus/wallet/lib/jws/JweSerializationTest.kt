package at.asitplus.wallet.lib.jws

import at.asitplus.crypto.datatypes.jws.JweAlgorithm
import at.asitplus.crypto.datatypes.jws.JweEncryption
import at.asitplus.crypto.datatypes.jws.JweHeader
import at.asitplus.crypto.datatypes.jws.JwsContentTypeConstants
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
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

        val serialized = jweHeader.serialize()

        serialized shouldContain """"${algorithm.text}""""
        serialized shouldContain """"${encryption.text}""""
        serialized shouldContain """"$kid""""
        serialized shouldContain """"$type""""
    }

    "Deserialization is correct" {
        val kid = uuid4().toString()
        val algorithm = JweAlgorithm.ECDH_ES
        val encryption = JweEncryption.A256GCM
        val type = JwsContentTypeConstants.JWT
        val serialized = """{"alg": "${algorithm.text}", "enc": "${encryption.text}", "kid": "$kid", "typ": "$type"}"""

        val parsed = JweHeader.deserialize(serialized)

        parsed.shouldNotBeNull()
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

        val parsed = JweHeader.deserialize(serialized)

        parsed.shouldNotBeNull()
        parsed.algorithm shouldBe null
        parsed.encryption shouldBe encryption
        parsed.keyId shouldBe kid
        parsed.type shouldBe type
    }

    "Deserialization with unknown encryption is correct" {
        val kid = uuid4().toString()
        val algorithm = JweAlgorithm.ECDH_ES
        val type = JwsContentTypeConstants.JWT
        val serialized = """{"alg": "${algorithm.text}", "enc": "foo", "kid": "$kid", "typ": "$type"}"""

        val parsed = JweHeader.deserialize(serialized)

        parsed.shouldNotBeNull()
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
        val serialized = """{"alg": "${algorithm.text}", "enc": "${encryption.text}", "kid": "$kid", "typ": "$type"}"""

        val parsed = JweHeader.deserialize(serialized)

        parsed.shouldNotBeNull()
        parsed.algorithm shouldBe algorithm
        parsed.encryption shouldBe encryption
        parsed.keyId shouldBe kid
        parsed.type shouldBe type
    }

})
