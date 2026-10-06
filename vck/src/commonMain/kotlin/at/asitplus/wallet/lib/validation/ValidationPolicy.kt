package at.asitplus.wallet.lib.validation

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import kotlin.jvm.JvmOverloads
import kotlin.time.Duration

/**
 * Whether the signer of an artifact has to be authorized by trust anchors: the issuer of a credential, the signer of
 * a status list token, a wallet provider, a relying party, ...
 */
sealed interface TrustPolicy {
    /**
     * The signature is checked against the key the artifact asserts itself, but no trust decision is required.
     * This is an explicit interoperability choice, not a synonym for trusted.
     */
    data object IntegrityOnly : TrustPolicy

    /** The signing certificate has to chain to an anchor configured for the artifact. */
    data object RequireAuthorizedSigner : TrustPolicy
}

/**
 * Whether and how the status of an artifact is checked.
 * Every advertised status mechanism is resolved, and all of them have to yield an
 * [accepted][ValidateIfPresent.accepted] and agreeing status.
 */
sealed interface StatusPolicy {
    /** The status is not checked, even if the artifact advertises one. */
    data object Skip : StatusPolicy

    /** The status is checked if the artifact advertises one, an artifact without a status claim passes. */
    data class ValidateIfPresent @JvmOverloads constructor(
        /** Whether the signers of the status list tokens have to be authorized, independently of the artifact's. */
        val signerTrust: TrustPolicy,
        val accepted: Set<TokenStatus> = setOf(TokenStatus.Valid),
    ) : StatusPolicy {
        init {
            require(accepted.isNotEmpty()) { "At least one token status has to be accepted" }
        }
    }

    /** The artifact has to advertise a status, and that status is checked. */
    data class RequireClaim @JvmOverloads constructor(
        /** Whether the signers of the status list tokens have to be authorized, independently of the artifact's. */
        val signerTrust: TrustPolicy,
        val accepted: Set<TokenStatus> = setOf(TokenStatus.Valid),
    ) : StatusPolicy {
        init {
            require(accepted.isNotEmpty()) { "At least one token status has to be accepted" }
        }
    }
}

/**
 * Which checks have to pass for an artifact to be accepted.
 *
 * There is deliberately no default and no preset: callers choose whether signers have to be authorized, whether a
 * status is checked, and whether an artifact outside its validity period is rejected. Parsing, signatures, and the
 * binding of holder proofs to the request can not be relaxed.
 */
data class ValidationPolicy(
    val trust: TrustPolicy,
    val status: StatusPolicy,
    /** Applied to every time comparison of a validation, including the time claims of holder proofs. */
    val timeLeeway: Duration,
    /**
     * Whether an artifact that is not valid at the time of validation is rejected. The time claims of holder proofs,
     * e.g. the `iat` of a key binding JWT, are always required: relaxing them would relax replay protection.
     */
    val requireTimeliness: Boolean,
) {
    init {
        require(timeLeeway.isFinite() && !timeLeeway.isNegative()) { "Time leeway has to be finite and not negative" }
    }
}

/**
 * Whether a standalone credential has to be bound to a key the caller expects, e.g. the wallet's key when storing it.
 *
 * Presentations take holder binding from the request instead, see [PresentationContext.requireHolderBinding].
 */
sealed interface HolderBindingPolicy {
    /** The credential's holder binding is not compared to any key. */
    data object None : HolderBindingPolicy

    /** The credential has to be bound to [CredentialValidationContext.expectedHolderKey]. */
    data object RequireExpectedKey : HolderBindingPolicy
}

/**
 * Values the caller expects of a credential, e.g. from the negotiated credential configuration or the request.
 *
 * These constrain the credential, but never replace the identity signed into it: in particular,
 * [expectedCredentialIdentifier] does not select trust anchors for a credential whose signed type differs.
 */
data class CredentialValidationContext @JvmOverloads constructor(
    /** The key the credential has to be bound to, see [HolderBindingPolicy.RequireExpectedKey]. */
    val expectedHolderKey: CryptoPublicKey? = null,
    /** The signed `vct`, `docType`, or VC type the credential has to carry. */
    val expectedCredentialIdentifier: String? = null,
)
