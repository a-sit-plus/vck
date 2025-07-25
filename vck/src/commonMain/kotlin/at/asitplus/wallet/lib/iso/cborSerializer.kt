package at.asitplus.wallet.lib.iso

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.supreme.hash.digest

@Deprecated("Moved", ReplaceWith("sha256()", "at.asitplus.iso.sha256"))
fun ByteArray.sha256(): ByteArray = Digest.SHA256.digest(this)