package at.asitplus.wallet.lib.agent

import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.iso.Document
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull


/**
 * An agent that only implements [Verifier], i.e. it can only verify credentials of other agents.
 */
class VerifierAgent private constructor(
    private val validator: Validator,
    override val identifier: String
) : Verifier {

    companion object {
        fun newDefaultInstance(
            identifier: String,
            cryptoService: VerifierCryptoService = DefaultVerifierCryptoService(),
            validator: Validator = Validator.newDefaultInstance(cryptoService),
        ): VerifierAgent = VerifierAgent(
            validator = validator,
            identifier = identifier
        )

        /**
         * Explicitly short argument list to use it from Swift
         */
        fun newDefaultInstance(identifier: String): VerifierAgent = VerifierAgent(
            validator = Validator.newDefaultInstance(),
            identifier = identifier
        )

        /**
         * Creates a new verifier for a random `identifier`
         */
        fun newRandomInstance(): VerifierAgent = VerifierAgent(
            validator = Validator.newDefaultInstance(),
            identifier = DefaultCryptoService().jsonWebKey.identifier,
        )
    }

    override fun setRevocationList(it: String): Boolean {
        return validator.setRevocationList(it)
    }

    /**
     * Verifies a presentation of some credentials that a holder issued with that [challenge] we sent before.
     */
    override fun verifyPresentation(it: String, challenge: String): Verifier.VerifyPresentationResult {
        val jwsSigned = runCatching { JwsSigned.parse(it) }.getOrNull()
        if (jwsSigned != null) {
            return validator.verifyVpJws(it, challenge, identifier)
        }
        val document =
            runCatching {
                it.decodeToByteArrayOrNull(Base16(strict = true))?.let { bytes -> Document.deserialize(bytes) }
            }.getOrNull()
        if (document != null) {
            return validator.verifyDocument(document, challenge)
        }
        return Verifier.VerifyPresentationResult.InvalidStructure(it)
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
        return validator.verifyVcJws(it, identifier)
    }

}
