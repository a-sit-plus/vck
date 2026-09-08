package at.asitplus.wallet.lib.agent.validation.relyingParty

import at.asitplus.catchingUnwrapped
import at.asitplus.iso.sha256
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString


fun X509Certificate.shortFingerprint() = catchingUnwrapped {
    val full = this.encodeToDer().sha256().encodeToString(Base16Strict)
    if (full.length <= 24) full else full.take(24) + "..."
}.getOrNull()
