package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.CwtStatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.JwtStatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.StatusListTokenPayloadSurrogate
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.serialization.FormatTransformingSerializerTemplate
import kotlinx.serialization.KSerializer

/**
 * Workaround to support serialization without type discriminator.
 */
object StatusListTokenPayloadSerializer :
    KSerializer<StatusListTokenPayload> by FormatTransformingSerializerTemplate(
        fallbackTransformer = TransformingSerializerTemplate(
            parent = StatusListTokenPayloadSurrogate.serializer(),
            encodeAs = {
                StatusListTokenPayloadSurrogate(it)
            },
            decodeAs = {
                it.toStatusListTokenPayload()
            },
        ),
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
