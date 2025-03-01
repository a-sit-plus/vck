package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
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

    /**
     * Parses a Verifiable Credential in JWS format
     *
     * @param it the JWS enclosing the VC, in compact representation
     */
    fun parseVcJws(it: String, vcJws: VerifiableCredentialJws): ParseVcResult {
        if (vcJws.issuer != vcJws.vc.issuer)
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.w("iss invalid: ${vcJws.issuer}, expected ${vcJws.vc.issuer}") }
        if (vcJws.jwtId != vcJws.vc.id)
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.w("jti invalid: ${vcJws.jwtId}, expected ${vcJws.vc.id}") }
        if (vcJws.subject != vcJws.vc.credentialSubject.id)
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.w("sub invalid: ${vcJws.subject}, expected ${vcJws.vc.credentialSubject.id}") }
        if (!vcJws.vc.type.contains(VERIFIABLE_CREDENTIAL))
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.w("type invalid: ${vcJws.vc.type}, expected to contain $VERIFIABLE_CREDENTIAL") }
        if (vcJws.expiration != null && vcJws.expiration < (clock.now() - timeLeeway))
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.w("exp invalid: ${vcJws.expiration}, now is ${clock.now()}") }
        if (vcJws.vc.expirationDate != null && vcJws.vc.expirationDate < (clock.now() - timeLeeway))
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.w("expirationDate invalid: ${vcJws.vc.expirationDate}, now is ${clock.now()}") }
        if (vcJws.expiration?.epochSeconds != vcJws.vc.expirationDate?.epochSeconds)
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.w("exp invalid: ${vcJws.expiration}, expected ${vcJws.vc.expirationDate}") }
        if (vcJws.notBefore > (clock.now() + timeLeeway))
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.w("nbf invalid: ${vcJws.notBefore}, now is ${clock.now()}") }
        if (vcJws.vc.issuanceDate > (clock.now() + timeLeeway))
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.w("issuanceDate invalid: ${vcJws.vc.issuanceDate}, now is ${clock.now()}") }
        if (vcJws.notBefore.epochSeconds != vcJws.vc.issuanceDate.epochSeconds)
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.w("nbf invalid: ${vcJws.notBefore}, expected ${vcJws.vc.issuanceDate}") }
        Napier.d("VC is valid")
        return ParseVcResult.Success(vcJws)
    }

    /**
     * Verifies the time validity of a [VerifiableCredentialSdJwt]
     */
    fun verifySdJwtValidity(sdJwt: VerifiableCredentialSdJwt): ParseVcResult {
        if (sdJwt.expiration != null && sdJwt.expiration < (clock.now() - timeLeeway)) {
            Napier.w("exp invalid: ${sdJwt.expiration}, now is ${clock.now()}")
            return ParseVcResult.ValidationError("exp invalid: ${sdJwt.expiration}, now is ${clock.now()}")
        }
        if (sdJwt.notBefore != null && sdJwt.notBefore > (clock.now() + timeLeeway)) {
            Napier.w("nbf invalid: ${sdJwt.notBefore}, now is ${clock.now()}")
            return ParseVcResult.ValidationError("nbf invalid: ${sdJwt.notBefore}, now is ${clock.now()}")
        }
        Napier.d("SD-JWT is valid")
        return ParseVcResult.SuccessSdJwt(sdJwt)
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

