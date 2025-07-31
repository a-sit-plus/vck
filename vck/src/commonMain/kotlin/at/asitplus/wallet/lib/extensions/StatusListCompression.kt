package at.asitplus.wallet.lib.extensions

import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView

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