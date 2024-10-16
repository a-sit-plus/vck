package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.iso.DeviceResponse
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.jws.SdJwtSigned
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull


/**
 * An agent that only implements [Verifier], i.e. it can only verify credentials of other agents.
 */
class VerifierAgent private constructor(
    private val validator: Validator,
    override val keyMaterial: KeyMaterial,
) : Verifier {

    constructor(keyPairAdapter: KeyMaterial) : this(
        validator = Validator(),
        keyMaterial = keyPairAdapter,
    )

    constructor(): this(
        validator = Validator(),
        keyMaterial = EphemeralKeyWithoutCert(),
    )

    override fun setRevocationList(it: String): Boolean {
        return validator.setRevocationList(it)
    }

    /**
     * Verifies a presentation of some credentials that a holder issued with that [challenge] we sent before.
     */
    override fun verifyPresentation(input: String, challenge: String): Verifier.VerifyPresentationResult {
        val sdJwtSigned = runCatching { SdJwtSigned.parse(input) }.getOrNull()
        if (sdJwtSigned != null) {
            return validator.verifyVpSdJwt(input, challenge, keyMaterial.publicKey)
        }
        val jwsSigned = JwsSigned.deserialize(input).getOrNull()
        if (jwsSigned != null) {
            return validator.verifyVpJws(input, challenge, keyMaterial.publicKey)
        }
        val document = input.decodeToByteArrayOrNull(Base16(false))
            ?.let { bytes -> Document.deserialize(bytes).getOrNull() }
        if (document != null) {
            val verifiedDocument = runCatching {
                validator.verifyDocument(document, challenge)
            }.getOrElse {
                return Verifier.VerifyPresentationResult.InvalidStructure(input)
            }
            return Verifier.VerifyPresentationResult.SuccessIso(listOf(verifiedDocument))
        }
        val deviceResponse = input.decodeToByteArrayOrNull(Base64UrlStrict)
            ?.let { bytes -> DeviceResponse.deserialize(bytes).getOrNull() }
        if (deviceResponse != null) {
            val result = runCatching {
                validator.verifyDeviceResponse(deviceResponse, challenge)
            }.getOrElse {
                return Verifier.VerifyPresentationResult.InvalidStructure(input)
            }
            return result
        }
        return Verifier.VerifyPresentationResult.InvalidStructure(input)
            .also { Napier.w("Could not verify presentation, unknown format: $it") }
    }

    /**
     * Verifies if a presentation contains all required [attributeNames].
     */
    override fun verifyPresentationContainsAttributes(
        it: VerifiablePresentationParsed,
        attributeNames: List<String>
    ): Boolean {
        val existingAttributeNames = it.verifiableCredentials
            .map { it.vc.credentialSubject }
            .filterIsInstance<AtomicAttribute2023>()
            .map { it.name }
        return attributeNames == existingAttributeNames
    }

    override fun verifyVcJws(it: String): Verifier.VerifyCredentialResult {
        return validator.verifyVcJws(it, keyMaterial.publicKey)
    }

}
