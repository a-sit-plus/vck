package at.asitplus.wallet.lib.extensions

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JwkType
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

/**
 * Selects the first key that the authn response can be encrypted for,
 * i.e. one with `enc` key use, or `ECDH-ES` algorithm.
 */
fun Collection<JsonWebKey>.getEncryptionTargetKey(): JsonWebKey? =
    filter { it.type == JwkType.EC }.let { ecKeys ->
        ecKeys.firstOrNull { it.publicKeyUse == "enc" }
            ?: ecKeys.firstOrNull { it.algorithm == JweAlgorithm.ECDH_ES }
            ?: ecKeys.firstOrNull()
    }

fun Collection<JsonWebKey>.firstSessionTranscriptThumbprint(): ByteArray? =
    getEncryptionTargetKey()?.sessionTranscriptThumbprint()

fun JsonWebKey.sessionTranscriptThumbprint(): ByteArray =
    jwkThumbprint.removePrefix("urn:ietf:params:oauth:jwk-thumbprint:sha256:")
        .decodeToByteArray(Base64UrlStrict)