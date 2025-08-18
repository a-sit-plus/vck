package at.asitplus.requests

import at.asitplus.openid.TransactionDataBase64Url

//TODO Overhaul
interface RequestParameters {
    val responseType: String?
    val nonce: String?
    val clientId: String?
    val responseUrl: String?
    val state: String?
}



