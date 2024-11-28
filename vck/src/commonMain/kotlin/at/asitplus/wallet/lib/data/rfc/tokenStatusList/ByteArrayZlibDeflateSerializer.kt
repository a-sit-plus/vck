package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.wallet.lib.DefaultZlibService
import kotlinx.serialization.builtins.ByteArraySerializer

object ByteArrayZlibDeflateSerializer : TransformingSerializerTemplate<ByteArray, ByteArray>(
    parent = ByteArraySerializer(),
    encodeAs = {
        DefaultZlibService().compress(it) ?: throw IllegalArgumentException("Argument must be zlib-compressible.")
    },
    decodeAs = {
        DefaultZlibService().decompress(it) ?: throw IllegalArgumentException("Argument must be zlib-decompressible.")
    }
)