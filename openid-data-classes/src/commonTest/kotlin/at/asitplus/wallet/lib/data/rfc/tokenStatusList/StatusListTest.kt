package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

@OptIn(ExperimentalUnsignedTypes::class)
val StatusListTest by testSuite {
    "byte array correctness" - {
        "tokenStatus1 list" - {
            withData(
                mapOf(
                    "requires 0 bytes for 0 statuses" to Pair(
                        listOf(),
                        ByteArray(0) {
                            0.toByte()
                        }
                    ),
                    "is remaining filled with zeros" to Pair(
                        (1..4).map {
                            TokenStatus(0u)
                        },
                        ByteArray(1) {
                            0.toByte()
                        }
                    ),
                    "fits 8 statuses into 1 byte" to Pair(
                        (1..8).map {
                            TokenStatus(0u)
                        },
                        ByteArray(1) {
                            0.toByte()
                        }
                    ),
                    "fits 9 statuses into 2 bytes" to Pair(
                        (1..9).map {
                            TokenStatus(0u)
                        },
                        ByteArray(2) {
                            0.toByte()
                        }
                    ),
                )
            ) { (values, expectedByteArray) ->
                StatusListView.fromTokenStatuses(
                    values,
                    statusBitSize = TokenStatusBitSize.ONE,
                ).uncompressed shouldBe expectedByteArray
            }
        }
        "tokenStatus2 list" - {
            withData(
                mapOf(
                    "requires 0 bytes for 0 statuses" to Pair(
                        listOf(),
                        ByteArray(0) {
                            0.toByte()
                        }
                    ),
                    "is remaining filled with zeros" to Pair(
                        (1..5).map {
                            TokenStatus(0u)
                        },
                        ByteArray(2) {
                            0.toByte()
                        }
                    ),
                    "fits 4 statuses into 1 byte" to Pair(
                        (1..4).map {
                            TokenStatus(0u)
                        },
                        ByteArray(1) {
                            0.toByte()
                        }
                    ),
                    "fits 5 statuses into 2 bytes" to Pair(
                        (1..5).map {
                            TokenStatus(0u)
                        },
                        ByteArray(2) {
                            0.toByte()
                        }
                    ),
                    "is first byte filling least significant bits" to Pair(
                        listOf(
                            TokenStatus(1u)
                        ),
                        ByteArray(1) {
                            1.toByte()
                        }
                    ),
                    "is fourth byte filling most significant bits" to Pair(
                        listOf(
                            TokenStatus(0u),
                            TokenStatus(0u),
                            TokenStatus(0u),
                            TokenStatus(1u),
                        ),
                        ByteArray(1) {
                            0x40.toByte()
                        }
                    ),
                    "is fith byte filling least significant bits" to Pair(
                        listOf(
                            TokenStatus(0u),
                            TokenStatus(0u),
                            TokenStatus(0u),
                            TokenStatus(0u),
                            TokenStatus(1u),
                        ),
                        ByteArray(2) { index ->
                            (if(index == 0) 0 else 1).toByte()
                        }
                    ),
                )
            ) { (values, expectedByteArray) ->
                StatusListView.fromTokenStatuses(
                    values,
                    statusBitSize = TokenStatusBitSize.TWO,
                ).uncompressed shouldBe expectedByteArray
            }
        }
        "tokenStatus4 list" - {
            withData(
                mapOf(
                    "requires 0 bytes for 0 statuses" to Pair(
                        listOf(),
                        ByteArray(0) {
                            0.toByte()
                        },
                    ),
                    "is remaining filled with zeros" to Pair(
                        (1..3).map {
                            TokenStatus(0u)
                        },
                        ByteArray(2) {
                            0.toByte()
                        },
                    ),
                    "fits 2 statuses into 1 byte" to Pair(
                        (1..2).map {
                            TokenStatus(0u)
                        },
                        ByteArray(1) {
                            0.toByte()
                        },
                    ),
                    "fits 3 statuses into 2 bytes" to Pair(
                        (1..3).map {
                            TokenStatus(0u)
                        },
                        ByteArray(2) {
                            0.toByte()
                        },
                    ),
                    "is first byte filling least significant bits" to Pair(
                        listOf(
                            TokenStatus(1u)
                        ),
                        ByteArray(1) {
                            1.toByte()
                        },
                    ),
                    "is second byte filling most significant bits" to Pair(
                        listOf(
                            TokenStatus(0u),
                            TokenStatus(1u),
                        ),
                        ByteArray(1) {
                            0x10.toByte()
                        }
                    ),
                    "is third byte filling least significant bits" to Pair(
                        listOf(
                            TokenStatus(0u),
                            TokenStatus(0u),
                            TokenStatus(1u),
                        ),
                        ByteArray(2) { index ->
                            (if(index == 0) 0 else 1).toByte()
                        }
                    ),
                )
            ) { (values, expectedByteArray) ->
                StatusListView.fromTokenStatuses(
                    values,
                    statusBitSize = TokenStatusBitSize.FOUR,
                ).uncompressed shouldBe expectedByteArray
            }
        }
        "tokenStatus8 list" - {
            withData(
                mapOf(
                    "requires 0 bytes for 0 statuses" to Pair(
                        listOf(),
                        ByteArray(0) {
                            0.toByte()
                        }
                    ),
                    "is remaining filled with zeros" to Pair(
                        (1..3).map {
                            TokenStatus(0u)
                        },
                        ByteArray(3) {
                            0.toByte()
                        }
                    ),
                    "fits 1 statuses into 1 byte" to Pair(
                        (1..1).map {
                            TokenStatus(0u)
                        },
                        ByteArray(1) {
                            0.toByte()
                        }
                    ),
                    "fits 2 statuses into 2 bytes" to Pair(
                        (1..2).map {
                            TokenStatus(0u)
                        },
                        ByteArray(2) {
                            0.toByte()
                        }
                    ),
                )
            ) { (values, expectedByteArray) ->
                StatusListView.fromTokenStatuses(
                    values,
                    statusBitSize = TokenStatusBitSize.EIGHT,
                ).uncompressed shouldBe expectedByteArray
            }
        }
    }
}