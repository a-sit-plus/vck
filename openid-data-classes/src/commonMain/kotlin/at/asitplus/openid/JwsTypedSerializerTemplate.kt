package at.asitplus.openid

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.JWS
import at.asitplus.signum.indispensable.josef.JwsTyped
import kotlinx.serialization.KSerializer

@Deprecated("Will move into Signum in the next release", level = DeprecationLevel.WARNING)
class JwsTypedSerializerTemplate<J : JWS, P>(
    jwsSerializer: KSerializer<J>,
    private val payloadSerializer: KSerializer<P>,
) : TransformingSerializerTemplate<JwsTyped<J, P>, J>(
    parent = jwsSerializer,
    encodeAs = { it.jws },
    decodeAs = { jws -> JwsTyped(jws, jws.getPayload(payloadSerializer).getOrThrow()) }
)
