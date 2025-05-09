package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_PRESENTATION
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.DurationUnit
import kotlin.time.toDuration


/**
 * Parses Verifiable Credentials and Verifiable Presentations.
 * Does not verify the cryptographic authenticity of the data.
 * Does not verify the revocation status of the data.
 */
class Parser(
    timeLeewaySeconds: Long = 300L,
    private val clock: Clock = Clock.System,
) {

    private val timeLeeway = timeLeewaySeconds.toDuration(DurationUnit.SECONDS)

    /**
     * Parses a Verifiable Presentation in JWS format
     *
     * @param input the JWS enclosing the VP, in compact representation
     * @param challenge the nonce sent from the verifier to the holder creating the VP
     * @param clientId the identifier of the verifier that has requested the VP from the holder
     */
    fun parseVpJws(input: String, challenge: String, clientId: String): ParseVpResult {
        Napier.d("Parsing VP $input")
        val jws = JwsSigned.deserialize<VerifiablePresentationJws>(
            VerifiablePresentationJws.serializer(),
            input,
            vckJsonSerializer
        ).getOrNull()
            ?: return ParseVpResult.InvalidStructure(input)
                .also { Napier.w("Could not parse JWS: $input") }
        return parseVpJws(jws.payload, challenge, clientId)
    }

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

    sealed class ParseVcResult {
        data class Success(val jws: VerifiableCredentialJws) : ParseVcResult()
        data class SuccessSdJwt(val sdJwt: VerifiableCredentialSdJwt) : ParseVcResult()
        data class InvalidStructure(val input: String) : ParseVcResult()
        data class ValidationError(val cause: Throwable) : ParseVcResult() {
            constructor(message: String) : this(Throwable(message))
        }
    }

    sealed class ParseVpResult {
        data class Success(val jws: VerifiablePresentationJws) : ParseVpResult()
        data class InvalidStructure(val input: String) : ParseVpResult()
        data class ValidationError(val cause: Throwable) : ParseVpResult() {
            constructor(message: String) : this(Throwable(message))
        }
    }
}

