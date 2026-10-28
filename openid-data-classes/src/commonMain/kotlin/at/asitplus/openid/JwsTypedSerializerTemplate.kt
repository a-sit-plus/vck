package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JwsRaw
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsFlattened
import at.asitplus.signum.indispensable.josef.JwsGeneral
import at.asitplus.legacy.JwsHeader
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.JwsTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.typed
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonElement

/** Retain the request parameters and signed wire bytes while decoding headers and signatures. */
@Suppress("UNCHECKED_CAST")
internal fun <J : JwsRaw, P> J.typedWithPayload(payload: P): JwsTyped<J, JwsHeader, P> {
    val payloadSerializer = TransformingSerializerTemplate<P, JsonElement>(
        parent = JsonElement.serializer(),
        encodeAs = { joseCompliantSerializer.parseToJsonElement(plainPayload.decodeToString()) },
        decodeAs = { payload },
    )
    return when (this) {
        is JwsCompact.Raw -> typed(payloadSerializer, JwsHeader.serializer())
        is JwsFlattened.Raw -> typed(payloadSerializer, JwsHeader.serializer())
        is JwsGeneral.Raw -> typed(payloadSerializer, JwsHeader.serializer())
    } as JwsTyped<J, JwsHeader, P>
}
