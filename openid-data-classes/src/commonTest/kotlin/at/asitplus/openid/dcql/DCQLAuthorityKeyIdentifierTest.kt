package at.asitplus.openid.dcql

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.EncodingException

val DCQLAuthorityKeyIdentifierTest by testSuite {
    "given base64url string without padding" - {
        "when creating instance" - {
            "then does so successfully" - {
                withData(
                    "s9tIpPmhxdiuNkHMEWNpYim8S8Y"
                ) { string ->
                    val identifier = DCQLAuthorityKeyIdentifier(string)
                    identifier.byteArray shouldBe string.decodeToByteArray(Base64UrlStrict)
                }
            }
        }
    }
    "given base64url string with padding" - {
        "when creating instance" - {
            "then does so successfully" - {
                withData(
                    "s9tIpPmhxdiuNkHMEWNpYim8S8Y="
                ) { string ->
                    val identifier = DCQLAuthorityKeyIdentifier(string)
                    identifier.byteArray shouldBe string.decodeToByteArray(Base64UrlStrict)
                }
            }
        }
    }
    "given non-base64url string" - {
        "when creating instance" - {
            "then throws exception" - {
                withData(
                    "s9tIpPmhxdiuNkHMEWNpYim8S8!=",
                ) { string ->
                    shouldThrow<EncodingException> {
                        DCQLAuthorityKeyIdentifier(string)
                    }
                }
            }
        }
    }
}