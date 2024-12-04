package at.asitplus.openid

interface RequestParameters {
    val responseType: String?
    val nonce: String?
    val clientId: String?
    val redirectUrl: String?
    val audience: String?
    val state: String?
    val transactionData: Set<String>?
}



