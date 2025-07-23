package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.builtins.serializer

object TokenStatusBitSizeValueSerializer : TransformingSerializerTemplate<TokenStatusBitSize, UInt>(
    parent = UInt.serializer(),
    encodeAs = {
        it.value
    },
    decodeAs = {
        TokenStatusBitSize.valueOf(it)
    },
)

