import Foundation

// Kotlin's Duration parameters reach Swift as raw Int64 bits; these factories take seconds instead,
// and supply the Kotlin defaults that the Objective-C export drops.

public extension ValidationPolicy {
    /// Use this rather than `init(...timeLeeway:...)`, whose `Int64` is not a number of seconds.
    static func create(
        trust: TrustPolicy,
        status: StatusPolicy,
        timeLeeway: TimeInterval,
        requireTimeliness: Bool,
        holderBinding: HolderBindingPolicy = HolderBindingPolicyNone.shared,
        requiredClaims: RequiredClaimsPolicy = RequiredClaimsPolicySkip.shared,
        registration: RegistrationPolicy = RegistrationPolicyRequire.shared
    ) throws -> ValidationPolicy {
        try ValidationBridge.shared.policy(
            trust: trust, status: status, timeLeewaySeconds: timeLeeway, requireTimeliness: requireTimeliness,
            holderBinding: holderBinding, requiredClaims: requiredClaims, registration: registration
        )
    }
}

public extension StatusValidator {
    /// Without a resolver, a status claim is blocked. `nil` for `signatureCheck` or `zlibService` means Kotlin's default.
    static func create(
        statusListTokenResolver: StatusListTokenResolver? = nil,
        signatureCheck: SignatureCheck? = nil,
        zlibService: ZlibService? = nil
    ) -> StatusValidator {
        ValidationBridge.shared.statusValidator(
            statusListTokenResolver: statusListTokenResolver, signatureCheck: signatureCheck, zlibService: zlibService
        )
    }
}

public extension CredentialValidator {
    /// Without trust anchors, trust is blocked, so only integrity can be checked.
    /// `nil` for `signatureCheck` or `requiredClaimsResolver` means Kotlin's default.
    static func create(
        trustAnchors: CredentialTrustAnchors? = nil,
        statusValidator: StatusValidator = .create(),
        signatureCheck: SignatureCheck? = nil,
        clock: KotlinClock = ClockAdapter.system,
        requiredClaimsResolver: RequiredClaimsResolver? = nil
    ) -> CredentialValidator {
        ValidationBridge.shared.credentialValidator(
            trustAnchors: trustAnchors, statusValidator: statusValidator, signatureCheck: signatureCheck,
            clock: clock, requiredClaimsResolver: requiredClaimsResolver
        )
    }
}

public extension RelyingPartyTrustAnchors {
    /// A source left `nil` blocks trust for what it covers.
    static func create(
        accessCertificates: TrustedCertificates? = nil,
        registrationCertificates: TrustedCertificates? = nil,
        registrationStatus: TrustedCertificates? = nil,
        preRegisteredClients: PreRegisteredClients? = nil,
        verifierAttesters: VerifierAttesters? = nil,
        clientIdentifierPrefixes: ClientIdentifierTrust? = nil
    ) -> RelyingPartyTrustAnchors {
        RelyingPartyTrustAnchors(
            accessCertificates: accessCertificates, registrationCertificates: registrationCertificates,
            registrationStatus: registrationStatus, preRegisteredClients: preRegisteredClients,
            verifierAttesters: verifierAttesters, clientIdentifierPrefixes: clientIdentifierPrefixes
        )
    }
}

public extension RelyingPartyValidator {
    /// `maxRegistrationValidity` in seconds; by default 365 days (ETSI TS 119 475).
    /// `nil` for `signatureCheck` means Kotlin's default.
    static func create(
        trust: RelyingPartyTrustAnchors = .create(),
        statusValidator: StatusValidator = .create(),
        maxRegistrationValidity: TimeInterval = 365 * 24 * 60 * 60,
        signatureCheck: SignatureCheck? = nil,
        clock: KotlinClock = ClockAdapter.system
    ) throws -> RelyingPartyValidator {
        try ValidationBridge.shared.relyingPartyValidator(
            trust: trust, statusValidator: statusValidator, maxRegistrationValiditySeconds: maxRegistrationValidity,
            signatureCheck: signatureCheck, clock: clock
        )
    }
}

public extension IssuerMetadataValidator {
    /// Validates signed issuer metadata (WRPAC, WRPRC). A source left `nil` blocks trust for what it covers.
    /// `maxRegistrationValidity` in seconds; by default 365 days, as in Kotlin.
    /// `nil` for `signatureCheck` means Kotlin's default.
    static func create(
        accessCertificates: TrustedCertificates? = nil,
        registrationCertificates: TrustedCertificates? = nil,
        registrationStatus: TrustedCertificates? = nil,
        statusValidator: StatusValidator = .create(),
        maxRegistrationValidity: TimeInterval = 365 * 24 * 60 * 60,
        signatureCheck: SignatureCheck? = nil,
        clock: KotlinClock = ClockAdapter.system
    ) throws -> IssuerMetadataValidator {
        try ValidationBridge.shared.issuerMetadataValidator(
            accessCertificates: accessCertificates, registrationCertificates: registrationCertificates,
            registrationStatus: registrationStatus, statusValidator: statusValidator,
            maxRegistrationValiditySeconds: maxRegistrationValidity, signatureCheck: signatureCheck, clock: clock
        )
    }
}
