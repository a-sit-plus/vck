package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.validation.ClientAttestationValidator

/**
 * A wallet provider for tests: it signs client attestations with [signJwt], with a certificate issued by its CA,
 * which [clientAttestationValidator] trusts.
 */
class TestWalletProvider private constructor(
    private val authority: TestCertificateAuthority,
    private val keyMaterial: KeyMaterial,
) {
    val signJwt = SignJwt<JsonWebToken>(keyMaterial, JwsHeaderCertOrJwk())

    val clientAttestationValidator = ClientAttestationValidator(
        walletProviderAnchors = { setOf(authority.certificate) },
    )

    companion object {
        suspend operator fun invoke(): TestWalletProvider {
            val authority = TestCertificateAuthority()
            return TestWalletProvider(authority, authority.issue())
        }
    }
}
