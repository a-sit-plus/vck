package at.asitplus.wallet.lib

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView

interface ZlibService {

    fun compress(input: ByteArray): ByteArray?

    fun decompress(input: ByteArray): ByteArray?

}

expect class DefaultZlibService() : ZlibService {
    override fun compress(input: ByteArray): ByteArray?
    override fun decompress(input: ByteArray): ByteArray?
}

// TODO move to better file
fun StatusList.toView(zlibService: ZlibService = DefaultZlibService()) = StatusListView(
    // TODO  throw IllegalStateException("Member `compressed` must be zlib-deflate-uncompressible."),
    uncompressed = zlibService.decompress(compressed) ?: compressed,
    statusBitSize = statusBitSize,
)

fun StatusListView.toStatusList(zlibService: ZlibService, statusListAggregationUrl: String?): StatusList = StatusList(
    compressed = zlibService.compress(this.uncompressed) ?: this.uncompressed, // TODO Error handling
    statusBitSize = this.statusBitSize,
    aggregationUri = statusListAggregationUrl,
)
