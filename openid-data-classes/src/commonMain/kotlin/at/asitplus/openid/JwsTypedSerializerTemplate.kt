package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JWS
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsFlattened
import at.asitplus.signum.indispensable.josef.JwsFlattenedTyped
import at.asitplus.signum.indispensable.josef.JwsGeneral
import at.asitplus.signum.indispensable.josef.JwsGeneralTyped
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsHeaderWrapped
import at.asitplus.signum.indispensable.josef.JwsTyped
import kotlinx.serialization.KSerializer

@Deprecated("Moved into Signum; use its serializer with an explicit header serializer", level = DeprecationLevel.WARNING)
class JwsTypedSerializerTemplate<J : JWS, P>(
    jwsSerializer: KSerializer<J>,
    payloadSerializer: KSerializer<P>,
) : KSerializer<JwsTyped<J, P, JwsHeader>> by
    at.asitplus.signum.indispensable.josef.JwsTypedSerializerTemplate(
        jwsSerializer, payloadSerializer, JwsHeader.serializer()
    )

/** Retain the request parameters and signed wire bytes while decoding headers and signatures. */
@Suppress("UNCHECKED_CAST")
internal fun <J : JWS, P> J.typedWithPayload(payload: P): JwsTyped<J, P, JwsHeader> = when (this) {
    is JwsCompact -> JwsHeaderWrapped.fromParts(JwsHeader.serializer(), plainProtectedHeader, null).let {
        JwsCompactTyped(this, payload, it, JWS.getSignature(it.header.algorithm, plainSignature))
    }
    is JwsFlattened -> JwsHeaderWrapped.fromParts(
        JwsHeader.serializer(), plainProtectedHeader, unprotectedHeader
    ).let {
        JwsFlattenedTyped(this, payload, it, JWS.getSignature(it.header.algorithm, plainSignature))
    }
    is JwsGeneral -> signatureElements.map {
        JwsHeaderWrapped.fromParts(JwsHeader.serializer(), it.plainProtectedHeader, it.unprotectedHeader)
    }.let { headers ->
        JwsGeneralTyped(this, payload, headers, headers.zip(signatureElements) { header, signature ->
            JWS.getSignature(header.header.algorithm, signature.plainSignature)
        })
    }
} as JwsTyped<J, P, JwsHeader>
