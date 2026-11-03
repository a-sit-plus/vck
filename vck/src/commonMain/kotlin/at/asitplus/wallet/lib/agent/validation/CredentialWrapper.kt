@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.agent.validation

import at.asitplus.iso.IssuerSigned
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import kotlin.jvm.JvmInline

@Deprecated("Validate with at.asitplus.wallet.lib.validation.CredentialValidator, whose report holds every check. To be removed in the next major release.")
sealed interface CredentialWrapper {
    @JvmInline
    value class VcJws(val verifiableCredentialJws: VerifiableCredentialJws): CredentialWrapper

    @JvmInline
    value class SdJwt(val sdJwt: VerifiableCredentialSdJwt): CredentialWrapper

    @JvmInline
    value class Mdoc(val issuerSigned: IssuerSigned): CredentialWrapper
}