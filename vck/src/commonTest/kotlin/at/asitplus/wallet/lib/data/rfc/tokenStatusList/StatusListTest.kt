package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

@OptIn(ExperimentalUnsignedTypes::class)
class StatusListTest : FreeSpec({
    "byte array correctness" - {
        "tokenStatus1 list" - {
            withData(
                mapOf(
                    "requires 0 bytes for 0 statuses" to Pair(
                        listOf(),
                        UByteArray(0) {
                            0.toUByte()
                        }
                    ),
                    "is remaining filled with zeros" to Pair(
                        (1..4).map {
                            TokenStatus(0u)
                        },
                        UByteArray(1) {
                            0.toUByte()
                        }
                    ),
                    "fits 8 statuses into 1 byte" to Pair(
                        (1..8).map {
                            TokenStatus(0u)
                        },
                        UByteArray(1) {
                            0.toUByte()
                        }
                    ),
                    "fits 9 statuses into 2 bytes" to Pair(
                        (1..9).map {
                            TokenStatus(0u)
                        },
                        UByteArray(2) {
                            0.toUByte()
                        }
                    ),
                )
            ) { (values, expectedUByteArray) ->
                StatusListView.fromTokenStatuses(
                    values,
                    statusBitSize = TokenStatusBitSize.ONE,
                ).uncompressed shouldBe expectedUByteArray
            }
        }
        "tokenStatus2 list" - {
            withData(
                mapOf(
                    "requires 0 bytes for 0 statuses" to Pair(
                        listOf(),
                        UByteArray(0) {
                            0.toUByte()
                        }
                    ),
                    "is remaining filled with zeros" to Pair(
                        (1..5).map {
                            TokenStatus(0u)
                        },
                        UByteArray(2) {
                            0.toUByte()
                        }
                    ),
                    "fits 4 statuses into 1 byte" to Pair(
                        (1..4).map {
                            TokenStatus(0u)
                        },
                        UByteArray(1) {
                            0.toUByte()
                        }
                    ),
                    "fits 5 statuses into 2 bytes" to Pair(
                        (1..5).map {
                            TokenStatus(0u)
                        },
                        UByteArray(2) {
                            0.toUByte()
                        }
                    ),
                    "is first byte filling least significant bits" to Pair(
                        listOf(
                            TokenStatus(1u)
                        ),
                        UByteArray(1) {
                            1.toUByte()
                        }
                    ),
                    "is fourth byte filling most significant bits" to Pair(
                        listOf(
                            TokenStatus(0u),
                            TokenStatus(0u),
                            TokenStatus(0u),
                            TokenStatus(1u),
                        ),
                        UByteArray(1) {
                            0x40.toUByte()
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
                        UByteArray(2) { index ->
                            (if(index == 0) 0 else 1).toUByte()
                        }
                    ),
                )
            ) { (values, expectedUByteArray) ->
                StatusListView.fromTokenStatuses(
                    values,
                    statusBitSize = TokenStatusBitSize.TWO,
                ).uncompressed shouldBe expectedUByteArray
            }
        }
        "tokenStatus4 list" - {
            withData(
                mapOf(
                    "requires 0 bytes for 0 statuses" to Pair(
                        listOf(),
                        UByteArray(0) {
                            0.toUByte()
                        },
                    ),
                    "is remaining filled with zeros" to Pair(
                        (1..3).map {
                            TokenStatus(0u)
                        },
                        UByteArray(2) {
                            0.toUByte()
                        },
                    ),
                    "fits 2 statuses into 1 byte" to Pair(
                        (1..2).map {
                            TokenStatus(0u)
                        },
                        UByteArray(1) {
                            0.toUByte()
                        },
                    ),
                    "fits 3 statuses into 2 bytes" to Pair(
                        (1..3).map {
                            TokenStatus(0u)
                        },
                        UByteArray(2) {
                            0.toUByte()
                        },
                    ),
                    "is first byte filling least significant bits" to Pair(
                        listOf(
                            TokenStatus(1u)
                        ),
                        UByteArray(1) {
                            1.toUByte()
                        },
                    ),
                    "is second byte filling most significant bits" to Pair(
                        listOf(
                            TokenStatus(0u),
                            TokenStatus(1u),
                        ),
                        UByteArray(1) {
                            0x10.toUByte()
                        }
                    ),
                    "is third byte filling least significant bits" to Pair(
                        listOf(
                            TokenStatus(0u),
                            TokenStatus(0u),
                            TokenStatus(1u),
                        ),
                        UByteArray(2) { index ->
                            (if(index == 0) 0 else 1).toUByte()
                        }
                    ),
                )
            ) { (values, expectedUByteArray) ->
                StatusListView.fromTokenStatuses(
                    values,
                    statusBitSize = TokenStatusBitSize.FOUR,
                ).uncompressed shouldBe expectedUByteArray
            }
        }
        "tokenStatus8 list" - {
            withData(
                mapOf(
                    "requires 0 bytes for 0 statuses" to Pair(
                        listOf(),
                        UByteArray(0) {
                            0.toUByte()
                        }
                    ),
                    "is remaining filled with zeros" to Pair(
                        (1..3).map {
                            TokenStatus(0u)
                        },
                        UByteArray(3) {
                            0.toUByte()
                        }
                    ),
                    "fits 1 statuses into 1 byte" to Pair(
                        (1..1).map {
                            TokenStatus(0u)
                        },
                        UByteArray(1) {
                            0.toUByte()
                        }
                    ),
                    "fits 2 statuses into 2 bytes" to Pair(
                        (1..2).map {
                            TokenStatus(0u)
                        },
                        UByteArray(2) {
                            0.toUByte()
                        }
                    ),
                )
            ) { (values, expectedUByteArray) ->
                StatusListView.fromTokenStatuses(
                    values,
                    statusBitSize = TokenStatusBitSize.EIGHT,
                ).uncompressed shouldBe expectedUByteArray
            }
        }
    }
})