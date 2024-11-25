package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.DeviceResponse
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.jws.SdJwtSigned
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull


/**
 * An agent that only implements [Verifier], i.e. it can only verify credentials of other agents.
 */
class VerifierAgent(
    /**
     * The identifier of this verifier, that is expected to be the audience of verifiable presentations.
     * It may be a cryptographic identifier of the key, but can be anything, e.g. a URL.
     */
    private val identifier: String,
    private val validator: Validator = Validator(),
) : Verifier {

    override fun setRevocationList(it: String): Boolean {
        return validator.setRevocationList(it)
    }

    /**
     * Verifies a presentation of some credentials from a holder,
     * that shall include the [challenge] (sent by this verifier),
     * as well as the expected [identifier] (identifying this verifier).
     */
    override fun verifyPresentation(input: String, challenge: String): Verifier.VerifyPresentationResult {
        val sdJwtSigned = runCatching { SdJwtSigned.parse(input) }.getOrNull()
        if (sdJwtSigned != null) {
            return runCatching {
                validator.verifyVpSdJwt(input, challenge, identifier)
            }.getOrElse {
                Verifier.VerifyPresentationResult.InvalidStructure(input)
            }
        }
        val jwsSigned = JwsSigned.deserialize<VerifiablePresentationJws>(input, vckJsonSerializer).getOrNull()
        if (jwsSigned != null) {
            return runCatching {
                validator.verifyVpJws(input, challenge, identifier)
            }.getOrElse {
                Verifier.VerifyPresentationResult.InvalidStructure(input)
            }
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

}
