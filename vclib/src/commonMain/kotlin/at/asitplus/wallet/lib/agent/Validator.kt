package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.KmmBitSet
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.data.RevocationListSubject
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import io.matthewnelson.component.base64.decodeBase64ToArray
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JwsSigned
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.toBitSet
import io.github.aakira.napier.Napier


/**
 * Parses and validates Verifiable Credentials and Verifiable Presentations.
 * Does verify the cryptographic authenticity of the data, if a [verifierJwsService] is set on creation.
 * Does verify the revocation status of the data.
 */
class Validator(
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
    private val parser: Parser = Parser(),
    private val zlibService: ZlibService = DefaultZlibService(),
) {

    companion object {
        fun newDefaultInstance(
            cryptoService: VerifierCryptoService,
            parser: Parser = Parser()
        ) = Validator(
            verifierJwsService = DefaultVerifierJwsService(cryptoService = cryptoService),
            parser = parser
        )

        /**
         * Explicitly empty argument list to use it in Swift
         */
        fun newDefaultInstance() = Validator()
    }

    private var revocationList: KmmBitSet? = null

    /**
     * Sets the revocation list for verifying the revocation status of the VC
     * that will be later verified with [verifyVcJws].
     *
     * @return `true` if the revocation list was valid and has been set
     */
    fun setRevocationList(it: String): Boolean {
        Napier.d("setRevocationList: Loading $it")
        val jws = JwsSigned.parse(it)
            ?: return false
                .also { Napier.w("Revocation List: Could not parse JWS") }
        if (!verifierJwsService.verifyJwsObject(jws, it))
            return false
                .also { Napier.w("Revocation List: Signature invalid") }
        val payload = jws.payload.decodeToString()
        val kid = jws.header.keyId ?: return false.also { Napier.d("no kid in header") }
        val vcJws = VerifiableCredentialJws.deserialize(payload)
            ?: return false
                .also { Napier.w("Revocation List: Could not parse payload") }
        val parsedVc = parser.parseVcJws(it, vcJws, kid)
        if (parsedVc !is Parser.ParseVcResult.Success)
            return false
                .also { Napier.d("Revocation List: Could not parse VC: $parsedVc") }
        if (parsedVc.jws.vc.credentialSubject !is RevocationListSubject)
            return false
                .also { Napier.d("credentialSubject invalid") }
        val encodedList = parsedVc.jws.vc.credentialSubject.encodedList
        this.revocationList = encodedList.decodeBase64ToArray()?.let {
            zlibService.decompress(it)?.toBitSet() ?: return false.also { Napier.d("Invalid ZLIB") }
        } ?: return false.also { Napier.d("Invalid Base64") }
        Napier.d("Revocation list is valid")
        return true
    }

    enum class RevocationStatus {
        UNKNOWN,
        REVOKED,
        VALID;
    }

    /**
     * Checks the revocation state of the passed Verifiable Credential.
     *
     * Be sure to call [setRevocationList] first, otherwise this method will return [RevocationStatus.UNKNOWN].
     */
    fun checkRevocationStatus(vcJws: VerifiableCredentialJws): RevocationStatus {
        revocationList?.let { bitSet ->
            vcJws.vc.credentialStatus?.let { status ->
                if (bitSet.length() > status.index && bitSet[status.index])
                    return RevocationStatus.REVOKED
                return RevocationStatus.VALID
            }
        }
        return RevocationStatus.UNKNOWN
    }

    /**
     * Checks the revocation status of a Verifiable Credential with defined [statusListIndex].
     *
     * Be sure to call [setRevocationList] first, otherwise this method will return [RevocationStatus.UNKNOWN].
     */
    fun checkRevocationStatus(statusListIndex: Long): RevocationStatus {
        revocationList?.let { bitSet ->
            if (bitSet.length() > statusListIndex && bitSet[statusListIndex])
                return RevocationStatus.REVOKED
            return RevocationStatus.VALID
        }
        return RevocationStatus.UNKNOWN
    }

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Presentation.
     *
     * @param it JWS in compact representation
     * @param challenge Nonce that the verifier has sent to the holder
     * @param localId Local keyId of the verifier
     */
    fun verifyVpJws(
        it: String,
        challenge: String,
        localId: String
    ): Verifier.VerifyPresentationResult {
        Napier.d("Verifying VP $it")
        val jws = JwsSigned.parse(it)
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(it)
                .also { Napier.w("VP: Could not parse JWS") }
        if (!verifierJwsService.verifyJwsObject(jws, it))
            return Verifier.VerifyPresentationResult.InvalidStructure(it)
                .also { Napier.w("VP: Signature invalid") }
        val payload = jws.payload.decodeToString()
        val kid = jws.header.keyId ?: return Verifier.VerifyPresentationResult.InvalidStructure(it)
            .also { Napier.d("no kid in header") }
        val vpJws =
            kotlin.runCatching { VerifiablePresentationJws.deserialize(payload) }.getOrNull()
                ?: return Verifier.VerifyPresentationResult.InvalidStructure(it)
                    .also { Napier.w("VP: Could not parse payload") }
        val parsedVp = parser.parseVpJws(it, vpJws, kid, challenge, localId)
        if (parsedVp !is Parser.ParseVpResult.Success) {
            return Verifier.VerifyPresentationResult.InvalidStructure(it)
                .also { Napier.d("VP: Could not parse content") }
        }
        val parsedVcList = parsedVp.jws.vp.verifiableCredential
            .map { verifyVcJws(it, null) }
        val validVcList = parsedVcList
            .filterIsInstance<Verifier.VerifyCredentialResult.Success>()
            .map { it.jws }
        val revokedVcList = parsedVcList
            .filterIsInstance<Verifier.VerifyCredentialResult.Revoked>()
            .map { it.jws }
        val invalidVcList = parsedVcList
            .filterIsInstance<Verifier.VerifyCredentialResult.InvalidStructure>()
            .map { it.input }
        val vp = VerifiablePresentationParsed(
            parsedVp.jws.vp.id,
            parsedVp.jws.vp.type,
            validVcList.toTypedArray(),
            revokedVcList.toTypedArray(),
            invalidVcList.toTypedArray(),
        )
        Napier.d("VP: Valid")
        return Verifier.VerifyPresentationResult.Success(vp)
    }

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Credential.
     *
     * @param it JWS in compact representation
     * @param localId Optionally the local keyId, to verify VC was issued to correct subject
     */
    fun verifyVcJws(it: String, localId: String?): Verifier.VerifyCredentialResult {
        Napier.d("Verifying VC $it")
        val jws = JwsSigned.parse(it)
            ?: return Verifier.VerifyCredentialResult.InvalidStructure(it)
                .also { Napier.w("VC: Could not parse JWS") }
        if (!verifierJwsService.verifyJwsObject(jws, it))
            return Verifier.VerifyCredentialResult.InvalidStructure(it)
                .also { Napier.w("VC: Signature invalid") }
        val payload = jws.payload.decodeToString()
        val vcJws = VerifiableCredentialJws.deserialize(payload)
            ?: return Verifier.VerifyCredentialResult.InvalidStructure(it)
                .also { Napier.w("VC: Could not parse payload") }
        localId?.let {
            if (vcJws.subject != it)
                return Verifier.VerifyCredentialResult.InvalidStructure(it)
                    .also { Napier.d("VC: sub invalid") }
        }
        if (checkRevocationStatus(vcJws) == RevocationStatus.REVOKED)
            return Verifier.VerifyCredentialResult.Revoked(it, vcJws)
                .also { Napier.d("VC: revoked") }
        val kid = jws.header.keyId ?: return Verifier.VerifyCredentialResult.InvalidStructure(it)
            .also { Napier.d("VC: No kid in header") }
        return when (parser.parseVcJws(it, vcJws, kid)) {
            is Parser.ParseVcResult.InvalidStructure -> Verifier.VerifyCredentialResult.InvalidStructure(it)
                .also { Napier.d("VC: Invalid structure from Parser") }

            is Parser.ParseVcResult.Success -> Verifier.VerifyCredentialResult.Success(vcJws)
                .also { Napier.d("VC: Valid") }
        }
    }

}
