package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.DeviceResponse
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.MobileSecurityObject
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
    /**
     * Verifies a presentation of some credentials from a holder,
     * that shall include the [challenge] (sent by this verifier),
     * as well as the expected [identifier] (identifying this verifier).
     */
    @Deprecated("Use specific methods instead, to be deleted after 5.3.0")
    override suspend fun verifyPresentation(it: String, challenge: String): VerifyPresentationResult {
        val input = it
        val sdJwtSigned = runCatching { SdJwtSigned.parse(input) }.getOrNull()
        if (sdJwtSigned != null) {
            return runCatching {
                validator.verifyVpSdJwt(sdJwtSigned, challenge, identifier)
            }.getOrElse {
                VerifyPresentationResult.ValidationError(it)
            }
        }
        val jwsSigned = JwsSigned.deserialize(VerifiablePresentationJws.serializer(), input, vckJsonSerializer)
            .getOrNull()
        if (jwsSigned != null) {
            return runCatching {
                validator.verifyVpJws(jwsSigned, challenge, identifier)
            }.getOrElse {
                VerifyPresentationResult.ValidationError(it)
            }
        }
        val document = input.decodeToByteArrayOrNull(Base16(false))
            ?.let { bytes -> Document.deserialize(bytes).getOrNull() }
        if (document != null) {
            val verifiedDocument = runCatching {
                validator.verifyDocument(document) { mso, document ->
                    validator.verifyDocumentFallback(mso, document, challenge)
                }
            }.getOrElse {
                return VerifyPresentationResult.ValidationError(it)
            }
            return VerifyPresentationResult.SuccessIso(listOf(verifiedDocument))
        }
        val deviceResponse = input.decodeToByteArrayOrNull(Base64UrlStrict)
            ?.let { bytes -> DeviceResponse.deserialize(bytes).getOrNull() }
        if (deviceResponse != null) {
            val result = runCatching {
                validator.verifyDeviceResponse(deviceResponse) { mso, document ->
                    validator.verifyDocumentFallback(mso, document, challenge)
                }
            }.getOrElse {
                return VerifyPresentationResult.ValidationError(it)
            }
            return result
        }
        return VerifyPresentationResult.InvalidStructure(input)
            .also { Napier.w("Could not verify presentation, unknown format: $it") }
    }

    override suspend fun verifyPresentationSdJwt(
        input: SdJwtSigned,
        challenge: String,
    ): VerifyPresentationResult = runCatching {
        validator.verifyVpSdJwt(input, challenge, identifier)
    }.getOrElse {
        VerifyPresentationResult.ValidationError(it)
    }

    override suspend fun verifyPresentationVcJwt(
        input: JwsSigned<VerifiablePresentationJws>,
        challenge: String,
    ): VerifyPresentationResult = runCatching {
        validator.verifyVpJws(input, challenge, identifier)
    }.getOrElse {
        VerifyPresentationResult.ValidationError(it)
    }

    override suspend fun verifyPresentationIsoMdoc(
        input: DeviceResponse,
        challenge: String,
        verifyDocument: (MobileSecurityObject, Document) -> Boolean,
    ): VerifyPresentationResult = runCatching {
        validator.verifyDeviceResponse(input, verifyDocument)
    }.getOrElse {
        VerifyPresentationResult.ValidationError(it)
    }
}
