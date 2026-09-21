package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

private val statusListInfo = StatusListInfo(
    index = 74727U,
    uri = UniformResourceIdentifier("https://example.com/statuslist.cwt"),
)

private val identifierListInfo = IdentifierListInfo(
    identifier = byteArrayOf(0x78, 0x42),
    uri = UniformResourceIdentifier("https://example.com/identifierlist.cwt"),
)

val TokenStatusInfoSerializationTest by matrixSuite {
    "round-trip individual status mechanisms" {
        listOf(
            TokenStatusInfo.from(statusListInfo),
            TokenStatusInfo.from(identifierListInfo),
        ).forEach { value ->
            val encoded = coseCompliantSerializer.encodeToByteArray(TokenStatusInfo.serializer(), value)
            coseCompliantSerializer.decodeFromByteArray(TokenStatusInfo.serializer(), encoded) shouldBe value
        }
    }

    "decode multiple status mechanisms" {
        val encoded = coseCompliantSerializer.encodeToByteArray(
            TokenStatusInfo.serializer(),
            TokenStatusInfo(statusListInfo, identifierListInfo),
        )

        val decodedStatus = coseCompliantSerializer.decodeFromByteArray(
            RevocationListInfo.StatusSurrogateSerializer,
            encoded,
        ).shouldBeInstanceOf<StatusListInfo>()
        val decoded = decodedStatus.tokenStatusInfo

        decoded.statusList shouldBe statusListInfo
        decoded.identifierList shouldBe identifierListInfo
        decoded.mechanisms shouldBe listOf(statusListInfo, identifierListInfo)
        coseCompliantSerializer.encodeToByteArray(
            RevocationListInfo.StatusSurrogateSerializer,
            decodedStatus,
        ) shouldBe encoded
    }

    "reject empty status information" {
        shouldThrow<IllegalArgumentException> {
            TokenStatusInfo()
        }

        shouldThrow<IllegalArgumentException> {
            coseCompliantSerializer.decodeFromByteArray(
                TokenStatusInfo.serializer(),
                byteArrayOf(0xa0.toByte()),
            )
        }
    }
}
