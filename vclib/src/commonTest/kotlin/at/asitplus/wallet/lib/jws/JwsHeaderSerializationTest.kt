package at.asitplus.wallet.lib.jws

import io.matthewnelson.component.base64.Base64
import io.matthewnelson.component.base64.encodeBase64
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlin.random.Random

class JwsHeaderSerializationTest : FreeSpec({

    "Serialization contains x5c as strings" {
        val first = Random.nextBytes(32)
        val second = Random.nextBytes(32)
        val algorithm = JwsAlgorithm.ES256
        val kid = uuid4().toString()
        val type = JwsContentTypeConstants.JWT
        val header = JwsHeader(
            algorithm = algorithm,
            keyId = kid,
            type = type,
            certificateChain = arrayOf(first, second)
        )

        val serialized = header.serialize()

        serialized shouldContain """"${first.encodeBase64(Base64.Default)}""""
        serialized shouldContain """"${second.encodeBase64(Base64.Default)}""""
        serialized shouldContain """"$kid""""
    }

    "Deserialization is correct" {
        val first = Random.nextBytes(32)
        val second = Random.nextBytes(32)
        val algorithm = JwsAlgorithm.ES256
        val kid = uuid4().toString()
        val type = JwsContentTypeConstants.JWT

        val serialized =
            """{"alg": "${algorithm.text}", "kid": "$kid", "typ": "$type", "x5c":["${first.encodeBase64()}","${second.encodeBase64()}"]}"""

        val parsed = JwsHeader.deserialize(serialized)

        parsed.shouldNotBeNull()
        parsed.algorithm shouldBe algorithm
        parsed.keyId shouldBe kid
        parsed.type shouldBe type
        parsed.certificateChain.shouldNotBeNull()
        parsed.certificateChain?.shouldContain(first)
        parsed.certificateChain?.shouldContain(second)
    }

})
