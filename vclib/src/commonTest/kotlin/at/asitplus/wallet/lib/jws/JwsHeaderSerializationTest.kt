package at.asitplus.wallet.lib.jws


import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
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

        serialized shouldContain """"${first.encodeToString(Base64())}""""
        serialized shouldContain """"${second.encodeToString(Base64())}""""
        serialized shouldContain """"$kid""""
    }

    "Deserialization is correct" {
        val first = Random.nextBytes(32)
        val second = Random.nextBytes(32)
        val algorithm = JwsAlgorithm.ES256
        val kid = uuid4().toString()
        val type = JwsContentTypeConstants.JWT

        val serialized = """{
            | "alg": "${algorithm.text}",
            | "kid": "$kid",
            | "typ": "$type",
            | "x5c":["${first.encodeToString(Base64())}",
            | "${second.encodeToString(Base64())}"]}
            | """.trimMargin()

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
