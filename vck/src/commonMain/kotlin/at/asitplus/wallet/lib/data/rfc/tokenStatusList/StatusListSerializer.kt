package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.CborSerializableStatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.JsonSerializableStatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.StatusListSurrogate
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.serialization.FormatTransformingSerializerTemplate
import kotlinx.serialization.KSerializer

object StatusListSerializer : KSerializer<StatusList> by FormatTransformingSerializerTemplate(
    descriptor = StatusListSurrogate.serializer().descriptor,
    jsonTransformer = TransformingSerializerTemplate(
        parent = JsonSerializableStatusList.serializer(),
        encodeAs = {
            JsonSerializableStatusList(it)
        },
        decodeAs = {
            it.toStatusList()
        },
    ),
    cborTransformer = TransformingSerializerTemplate(
        parent = CborSerializableStatusList.serializer(),
        encodeAs = {
            CborSerializableStatusList(it)
        },
        decodeAs = {
            it.toStatusList()
        },
    ),
)
