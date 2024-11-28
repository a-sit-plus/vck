package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.builtins.serializer

object TokenStatusBitSizeValueSerializer : TransformingSerializerTemplate<TokenStatusBitSize, Int>(
    parent = Int.serializer(),
    encodeAs = {
        it.value
    },
    decodeAs = {
        TokenStatusBitSize.valueOf(it)
    },
)

