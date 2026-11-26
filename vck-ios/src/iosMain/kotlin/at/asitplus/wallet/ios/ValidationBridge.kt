package at.asitplus.wallet.ios

import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.validation.CredentialTrustAnchors
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.HolderBindingPolicy
import at.asitplus.wallet.lib.validation.IssuerMetadataValidator
import at.asitplus.wallet.lib.validation.RegistrationPolicy
import at.asitplus.wallet.lib.validation.RelyingPartyTrustAnchors
import at.asitplus.wallet.lib.validation.RelyingPartyValidator
import at.asitplus.wallet.lib.validation.RequiredClaimsPolicy
import at.asitplus.wallet.lib.validation.RequiredClaimsResolver
import at.asitplus.wallet.lib.validation.SignatureCheck
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.StatusValidator
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidationPolicy
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

/**
 * Kotlin defaults and [kotlin.time.Duration] conversions that Swift cannot express directly:
 * a `Duration` reaches Swift as its raw `Int64` encoding, not as a number of seconds.
 * A `null` argument stands for the Kotlin default.
 */
object ValidationBridge {
    @Throws(IllegalArgumentException::class)
    fun policy(
        trust: TrustPolicy,
        status: StatusPolicy,
        timeLeewaySeconds: Double,
        requireTimeliness: Boolean,
        holderBinding: HolderBindingPolicy,
        requiredClaims: RequiredClaimsPolicy,
        registration: RegistrationPolicy,
    ): ValidationPolicy = ValidationPolicy(
        trust = trust,
        status = status,
        timeLeeway = timeLeewaySeconds.seconds,
        requireTimeliness = requireTimeliness,
        holderBinding = holderBinding,
        requiredClaims = requiredClaims,
        registration = registration,
    )

    fun statusValidator(
        statusListTokenResolver: StatusListTokenResolver?,
        signatureCheck: SignatureCheck?,
        zlibService: ZlibService?,
    ): StatusValidator = StatusValidator(
        statusListTokenResolver = statusListTokenResolver,
        signatureCheck = signatureCheck ?: SignatureCheck(),
        zlibService = zlibService ?: DefaultZlibService(),
    )

    fun credentialValidator(
        trustAnchors: CredentialTrustAnchors?,
        statusValidator: StatusValidator,
        signatureCheck: SignatureCheck?,
        clock: Clock?,
        requiredClaimsResolver: RequiredClaimsResolver?,
    ): CredentialValidator = CredentialValidator(
        trustAnchors = trustAnchors,
        statusValidator = statusValidator,
        signatureCheck = signatureCheck ?: SignatureCheck(),
        clock = clock ?: Clock.System,
        requiredClaimsResolver = requiredClaimsResolver ?: RequiredClaimsResolver.Default,
    )

    @Throws(IllegalArgumentException::class)
    fun relyingPartyValidator(
        trust: RelyingPartyTrustAnchors,
        statusValidator: StatusValidator,
        maxRegistrationValiditySeconds: Double,
        signatureCheck: SignatureCheck?,
        clock: Clock?,
    ): RelyingPartyValidator = RelyingPartyValidator(
        trust = trust,
        statusValidator = statusValidator,
        signatureCheck = signatureCheck ?: SignatureCheck(),
        maxRegistrationValidity = maxRegistrationValiditySeconds.seconds,
        clock = clock ?: Clock.System,
    )

    @Throws(IllegalArgumentException::class)
    fun issuerMetadataValidator(
        accessCertificates: TrustedCertificates?,
        registrationCertificates: TrustedCertificates?,
        registrationStatus: TrustedCertificates?,
        statusValidator: StatusValidator,
        maxRegistrationValiditySeconds: Double,
        signatureCheck: SignatureCheck?,
        clock: Clock?,
    ): IssuerMetadataValidator = IssuerMetadataValidator(
        accessCertificates = accessCertificates,
        registrationCertificates = registrationCertificates,
        registrationStatus = registrationStatus,
        statusValidator = statusValidator,
        signatureCheck = signatureCheck ?: SignatureCheck(),
        maxRegistrationValidity = maxRegistrationValiditySeconds.seconds,
        clock = clock ?: Clock.System,
    )
}
