package at.asitplus.rqes.collection_entries

@Deprecated("Replaced by Interface at.asitplus.openid.TransactionData")
sealed class TransactionData {
    @Deprecated("Moved", replaceWith = ReplaceWith("QcertCreationAcceptance"))
    class QCertCreationAcceptance(): TransactionData()
    @Deprecated("Moved", replaceWith = ReplaceWith("QesAuthorization"))
    class QesAuthorization(): TransactionData()
}