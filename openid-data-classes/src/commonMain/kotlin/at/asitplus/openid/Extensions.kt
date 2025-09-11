package at.asitplus.openid

import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.josef.JwsAlgorithm

internal fun String.toJwsAlgorithm(): JwsAlgorithm? =
    JwsAlgorithm.entries.firstOrNull { it.identifier == this }

internal fun JwsAlgorithm.toSignatureAlgorithm(): SignatureAlgorithm? =
    (this as? JwsAlgorithm.Signature)?.algorithm

internal fun Int.toCoseAlgorithm(): CoseAlgorithm? =
    CoseAlgorithm.entries.firstOrNull { it.coseValue == this }

internal fun CoseAlgorithm.toSignatureAlgorithm(): SignatureAlgorithm? =
    (this as? CoseAlgorithm.Signature)?.algorithm
