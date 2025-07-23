package at.asitplus.wallet.lib.agent.validation

import at.asitplus.iso.IssuerSigned
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import kotlin.jvm.JvmInline

sealed interface CredentialWrapper {
    @JvmInline
    value class VcJws(val verifiableCredentialJws: VerifiableCredentialJws): CredentialWrapper

    @JvmInline
    value class SdJwt(val sdJwt: VerifiableCredentialSdJwt): CredentialWrapper

    @JvmInline
    value class Mdoc(val issuerSigned: IssuerSigned): CredentialWrapper
}