package at.asitplus.wallet.lib.openid

import at.asitplus.signum.supreme.UserInitiatedCancellationReason

/** The user's cancellation of a signature, e.g. of unlocking the key, in [this] or its causes; `null` if none. */
internal fun Throwable.getUserSignatureCancellationException(): UserInitiatedCancellationReason? {
    var current: Throwable? = this
    while (current != null) {
        if (current is UserInitiatedCancellationReason) {
            return current
        }
        current = current.cause
    }
    return null
}
