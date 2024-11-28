package at.asitplus.wallet.lib.data.rfc9110

fun interface HttpRequestResolver {
    suspend fun resolve(httpRequest: HttpRequestMessage): HttpResponseMessage
}