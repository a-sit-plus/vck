package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.jws.JwsSigned
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
    epochMillisecondsForValidation: Long? = null,
) {

    private val timeLeeway = timeLeewaySeconds.toDuration(DurationUnit.SECONDS)
    private val clock: Clock = epochMillisecondsForValidation?.let {
        FixedTimeClock(epochMillisecondsForValidation)
    } ?: Clock.System

    /**
     * Parses a Verifiable Presentation in JWS format
     *
     * @param it the JWS enclosing the VP, in compact representation
     * @param challenge the nonce sent from the verifier to the holder creating the VP
     * @param localIdentifier the keyId of the verifier that has requested the VP from the holder
     */
    fun parseVpJws(it: String, challenge: String, localIdentifier: String): ParseVpResult {
        Napier.d("Parsing VP $it")
        val jws = JwsSigned.parse(it)
            ?: return ParseVpResult.InvalidStructure(it)
                .also { Napier.w("Could not parse JWS") }
        val payload = jws.payload.decodeToString()
        val kid = jws.header.keyId
        val vpJws = kotlin.runCatching { VerifiablePresentationJws.deserialize(payload) }.getOrNull()
            ?: return ParseVpResult.InvalidStructure(it)
                .also { Napier.w("Could not parse payload") }
        return parseVpJws(it, vpJws, kid, challenge, localIdentifier)
    }

    fun parseVpJws(
        it: String,
        vpJws: VerifiablePresentationJws,
        kid: String? = null,
        challenge: String,
        localIdentifier: String
    ): ParseVpResult {
        if (vpJws.challenge != challenge)
            return ParseVpResult.InvalidStructure(it)
                .also { Napier.d("nonce invalid") }
        if (vpJws.audience != localIdentifier)
            return ParseVpResult.InvalidStructure(it)
                .also { Napier.d("aud invalid") }
        if (kid != null && vpJws.issuer != kid)
            return ParseVpResult.InvalidStructure(it)
                .also { Napier.d("iss invalid") }
        if (vpJws.jwtId != vpJws.vp.id)
            return ParseVpResult.InvalidStructure(it)
                .also { Napier.d("jti invalid") }
        if (vpJws.vp.type != "VerifiablePresentation")
            return ParseVpResult.InvalidStructure(it)
                .also { Napier.d("type invalid") }
        Napier.d("VP is valid")
        return ParseVpResult.Success(vpJws)
    }

    /**
     * Parses a Verifiable Credential in JWS format
     *
     * @param it the JWS enclosing the VC, in compact representation
     */
    fun parseVcJws(it: String, vcJws: VerifiableCredentialJws, kid: String? = null): ParseVcResult {
        if (kid != null && vcJws.issuer != kid)
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.d("iss invalid") }
        if (vcJws.issuer != vcJws.vc.issuer)
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.d("iss invalid") }
        if (vcJws.jwtId != vcJws.vc.id)
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.d("jti invalid") }
        if (vcJws.subject != vcJws.vc.credentialSubject.id)
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.d("sub invalid") }
        if (!vcJws.vc.type.contains("VerifiableCredential"))
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.d("type invalid") }
        if (vcJws.expiration != null && vcJws.expiration < (clock.now() - timeLeeway))
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.d("exp invalid") }
        if (vcJws.vc.expirationDate != null && vcJws.vc.expirationDate < (clock.now() - timeLeeway))
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.d("expirationDate invalid") }
        if (vcJws.expiration?.epochSeconds != vcJws.vc.expirationDate?.epochSeconds)
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.d("exp invalid") }
        if (vcJws.notBefore > (clock.now() + timeLeeway))
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.d("nbf invalid") }
        if (vcJws.vc.issuanceDate > (clock.now() + timeLeeway))
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.d("issuanceDate invalid") }
        if (vcJws.notBefore.epochSeconds != vcJws.vc.issuanceDate.epochSeconds)
            return ParseVcResult.InvalidStructure(it)
                .also { Napier.d("nbf invalid") }
        Napier.d("VC is valid")
        return ParseVcResult.Success(vcJws)
    }

    sealed class ParseVcResult {
        data class Success(val jws: VerifiableCredentialJws) : ParseVcResult()
        data class InvalidStructure(val input: String) : ParseVcResult()
    }

    sealed class ParseVpResult {
        data class Success(val jws: VerifiablePresentationJws) : ParseVpResult()
        data class InvalidStructure(val input: String) : ParseVpResult()
    }
}

