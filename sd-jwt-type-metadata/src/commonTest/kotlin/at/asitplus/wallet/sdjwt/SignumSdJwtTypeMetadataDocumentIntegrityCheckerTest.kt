package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny

@Suppress("unused")
val SignumW3cSubresourceIntegrityCheckerTest by matrixSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    testSuite("values") {
        data((mapOf(
                "alert('Hello, world.');" to "sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
            ).mapValues {
                it.key.encodeToByteArray() to W3cSubresourceIntegrityMetadata(it.value)
            }).values) test {
            shouldNotThrowAny {
                SignumW3cSubresourceIntegrityMetadataBuilder.checkIntegrity(
                    data = it.first,
                    integrityHash = it.second
                )
            }
        }
    }
}
