package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_PRESENTATION
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import io.github.aakira.napier.Napier


/**
 * Parses Verifiable Credentials and Verifiable Presentations.
 * Does not verify the cryptographic authenticity of the data.
 * Does not verify the revocation status of the data.
 */
class Parser {

    /**
     * Parses a Verifiable Presentation in JWS format
     *
     * @param vpJws the JWS enclosing the VP
     * @param challenge the nonce sent from the verifier to the holder creating the VP
     * @param clientId the identifier of the verifier that has requested the VP from the holder
     */
    fun parseVpJws(
        vpJws: VerifiablePresentationJws,
        challenge: String,
        clientId: String,
    ): ParseVpResult {
        if (vpJws.challenge != challenge) {
            Napier.w("nonce invalid")
            return ParseVpResult.ValidationError("nonce invalid")
        }
        if (clientId != vpJws.audience) {
            Napier.w("aud invalid: ${vpJws.audience}, expected $clientId}")
            return ParseVpResult.ValidationError("aud invalid: ${vpJws.audience}")
        }
        if (vpJws.jwtId != vpJws.vp.id) {
            Napier.w("jti invalid: ${vpJws.jwtId}, expected ${vpJws.vp.id}")
            return ParseVpResult.ValidationError("jti invalid: ${vpJws.jwtId}")
        }
        if (vpJws.vp.type != VERIFIABLE_PRESENTATION) {
            Napier.w("type invalid: ${vpJws.vp.type}, expected $VERIFIABLE_PRESENTATION")
            return ParseVpResult.ValidationError("type invalid: ${vpJws.vp.type}")
        }
        Napier.d("VP is valid")
        return ParseVpResult.Success(vpJws)
    }

    sealed class ParseVpResult {
        data class Success(val jws: VerifiablePresentationJws) : ParseVpResult()
        data class ValidationError(val cause: Throwable) : ParseVpResult() {
            constructor(message: String) : this(Throwable(message))
        }
    }
}

