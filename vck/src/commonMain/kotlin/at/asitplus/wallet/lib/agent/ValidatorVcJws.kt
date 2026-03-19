package at.asitplus.wallet.lib.agent

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: Get the public key from the JWS header when verifying a vp.
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidationResult.ContentValidationSummary
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidationResult.ParsingError
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidator
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_PRESENTATION
import at.asitplus.wallet.lib.data.VcJwsVerificationResultWrapper
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureFun
import io.github.aakira.napier.Napier
import kotlin.coroutines.cancellation.CancellationException

/**
 * Parses and validates Verifiable Credentials and Verifiable Presentations.
 * Does verify the cryptographic authenticity of the data.
 * Does verify the revocation status of the data (when a status information is encoded in the credential).
 */
class ValidatorVcJws(
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    private val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(verifySignature),
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(verifyJwsSignature),
    /** Structure / Integrity / Semantics validator. */
    private val vcJwsInputValidator: VcJwsInputValidator =
        VcJwsInputValidator(verifyJwsObject = verifyJwsObject),
    private val validator: Validator = Validator(),
) {
    internal fun checkCredentialTimeliness(vcJws: VerifiableCredentialJws) =
        validator.checkCredentialTimeliness(vcJws)

    suspend fun checkCredentialFreshness(vcJws: VerifiableCredentialJws) =
        validator.checkCredentialFreshness(vcJws)

    internal suspend fun checkRevocationStatus(vcJws: VerifiableCredentialJws) =
        validator.checkRevocationStatus(vcJws)

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Presentation.
     *
     * @param challenge Nonce that the verifier has sent to the holder
     * @param clientId Identifier of the verifier (i.e. the audience of the presentation)
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyVpJws(
        input: JwsCompact,
        challenge: String,
        clientId: String,
    ): KmmResult<VerifyPresentationResult.Success> = catching {
        Napier.d("Verifying VP $input with $challenge and $clientId")
        verifyJwsObject(input).getOrThrow()
        val vpJws = input.payload.validate(challenge, clientId)
        val vcValidationResults = vpJws.vp.verifiableCredential
            .map { it to verifyVcJws(it, input.header.publicKey, input) }

        val invalidVcList = vcValidationResults.filter {
            it.second.isFailure
        }.map {
            it.first
        }

        val verificationResultWithFreshnessSummary = vcValidationResults.map {
            it.second
        }.mapNotNull {
            it.getOrNull()?.jws
        }.map {
            VcJwsVerificationResultWrapper(
                vcJws = it,
                freshnessSummary = validator.checkCredentialFreshness(it),
            )
        }

        val vp = VerifiablePresentationParsed(
            jws = input,
            id = vpJws.vp.id,
            type = vpJws.vp.type,
            freshVerifiableCredentials = verificationResultWithFreshnessSummary.filter {
                it.freshnessSummary.isFresh
            },
            notVerifiablyFreshVerifiableCredentials = verificationResultWithFreshnessSummary.filter {
                !it.freshnessSummary.isFresh
            },
            invalidVerifiableCredentials = invalidVcList,
        )
        Napier.d("VP: Valid")

        VerifyPresentationResult.Success(vp)
    }

    @Throws(IllegalArgumentException::class)
    fun VerifiablePresentationJws.validate(
        challenge: String,
        clientId: String,
    ): VerifiablePresentationJws {
        require(this.challenge == challenge) { "nonce invalid: ${this.challenge}, expected $challenge" }
        require(this.audience == clientId) { "aud invalid: ${this.audience}, expected $clientId" }
        require(this.jwtId == this.vp.id) { "jti invalid: ${this.jwtId}, expected ${this.vp.id}" }
        require(this.vp.type == VERIFIABLE_PRESENTATION) { "type invalid: ${this.vp.type}" }
        Napier.d("VP is valid")
        return this
    }

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Credential.
     *
     * @param input JWS in compact representation
     * @param publicKey Optionally, the local key, to verify VC was issued to the correct subject
     * @param vpJws Optionally, the VP enclosing the VC
     */
    suspend fun verifyVcJws(
        input: JwsCompact,
        publicKey: CryptoPublicKey,
        vpJws: JwsCompact? = null,
    ) = verifyVcJws(input.serialize(), publicKey, vpJws)

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Credential.
     *
     * @param input JWS in compact representation
     * @param publicKey Optionally, the local key, to verify VC was issued to the correct subject
     * @param vpJws Optionally, the VP enclosing the VC
     */
    suspend fun verifyVcJws(
        input: String,
        publicKey: CryptoPublicKey?,
        vpJws: JwsCompact? = null,
    ): KmmResult<VerifyCredentialResult.SuccessJwt> = catching {
        when (val result = vcJwsInputValidator(input, publicKey, vpJws)) {
            is ParsingError -> throw result.throwable
            is ContentValidationSummary -> if (result.isSuccess) {
                VerifyCredentialResult.SuccessJwt(result.payload)
            } else {
                throw ValidatiorVcJwsValidationException(result)
            }
        }.also {
            Napier.d("Validating VC-JWS $input got $it")
        }
    }
}

