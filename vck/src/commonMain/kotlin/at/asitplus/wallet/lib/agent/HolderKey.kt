package at.asitplus.wallet.lib.agent

import at.asitplus.catchingUnwrapped
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt

/** Whether a `cnf` is present, which SD-JWT VC, 2.2.2.3 requires if cryptographic key binding is supported. */
internal fun VerifiableCredentialSdJwt.isHolderBound(): Boolean = confirmationClaim != null

/** The key in `cnf` (SD-JWT VC, 2.2.2.3), if given by value (`jwk`). */
internal fun VerifiableCredentialSdJwt.holderKey(): CryptoPublicKey? = confirmationClaim.holderKey()

/** The `deviceKey` of the MSO, which every mdoc has (ETSI TS 119 472-1, EAA-6.5-01). */
internal fun MobileSecurityObject.holderKey(): CryptoPublicKey? = deviceKeyInfo.deviceKey.toCryptoPublicKey().getOrNull()

/**
 * Whether `sub` is a `did:key`, VC-K's convention for binding a VC-JWT to a key: VCDM 1.1 defines `sub` as the `id` of
 * the `credentialSubject` and no key binding, and only a `did:key` lets the key be derived from it. Any other `sub` is
 * not a key binding.
 */
internal fun VerifiableCredentialJws.isHolderBound(): Boolean = subject?.startsWith(DID_KEY_PREFIX) == true

/** The key of the `did:key` in `sub`, see [isHolderBound]. */
internal fun VerifiableCredentialJws.holderKey(): CryptoPublicKey? =
    subject?.takeIf { it.startsWith(DID_KEY_PREFIX) }
        ?.let { catchingUnwrapped { CryptoPublicKey.fromDid(it) }.getOrNull() }

private fun ConfirmationClaim?.holderKey(): CryptoPublicKey? = this?.jsonWebKey?.toCryptoPublicKey()?.getOrNull()

private const val DID_KEY_PREFIX = "did:key:"
