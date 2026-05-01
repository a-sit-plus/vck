package at.asitplus.rfc

import kotlinx.serialization.Serializable

@Serializable
data class Rfc3986Authority(
    val userInfo: Rfc3986UriAuthorityUserInformation?,
    val host: Rfc3986AuthorityHost,
    val port: ULong?,
) {
    companion object {
        operator fun invoke(string: String): Rfc3986Authority {
            val userInfoSeparatorIndex = string.indexOf('@').takeIf {
                it != -1
            }
            val ipLiteralEndSeparatorIndex = string.lastIndexOf(']').takeIf {
                it != -1
            }
            val portSeparatorIndex = string.lastIndexOf(':').takeIf {
                // : is otherwise only allowed in userinfo or in IP-literal
                it != -1 && (ipLiteralEndSeparatorIndex == null || it > ipLiteralEndSeparatorIndex)
                        && (userInfoSeparatorIndex == null || it > userInfoSeparatorIndex)
            }
            return Rfc3986Authority(
                userInfo = userInfoSeparatorIndex?.let {
                    Rfc3986UriAuthorityUserInformation(
                        string.substring(0, it)
                    )
                },
                host = Rfc3986AuthorityHost(
                    string.substring(
                        userInfoSeparatorIndex?.plus(1) ?: 0,
                        portSeparatorIndex ?: string.length
                    )
                ),
                port = portSeparatorIndex?.let {
                    string.substring(portSeparatorIndex + 1).toULong()
                }
            )
        }
    }

    fun toString(incldueSensitiveInformation: Boolean) = listOfNotNull(
        userInfo?.toString(incldueSensitiveInformation)?.let {
            "$it@"
        },
        host,
        port?.let {
            ":$it"
        }
    ).joinToString("")

    @Suppress("POTENTIALLY_NON_REPORTED_ANNOTATION")
    @Deprecated(
        "Usage of toString in authority is discouraged as a decision should be made on whether to include sensitive information within userInfo or not, if it exists.",
        ReplaceWith("toString(includeSensitiveInformation)")
    )
    override fun toString() = toString(false) // this may throw, but let's prefer that over exposin
}