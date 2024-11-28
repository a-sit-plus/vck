package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.CwtStatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.JwtStatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.StatusListTokenPayloadSurrogate
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.serialization.FormatTransformingSerializerTemplate
import kotlinx.serialization.KSerializer

object StatusListTokenPayloadSerializer :
    KSerializer<StatusListTokenPayload> by FormatTransformingSerializerTemplate(
        descriptor = StatusListTokenPayloadSurrogate.serializer().descriptor,
        jsonTransformer = TransformingSerializerTemplate(
            parent = JwtStatusListTokenPayload.serializer(),
            encodeAs = {
                JwtStatusListTokenPayload(it)
            },
            decodeAs = {
                it.toStatusListTokenPayload()
            },
        ),
        cborTransformer = TransformingSerializerTemplate(
            parent = CwtStatusListTokenPayload.serializer(),
            encodeAs = {
                CwtStatusListTokenPayload(it)
            },
            decodeAs = {
                it.toStatusListTokenPayload()
            },
        ),
    )
