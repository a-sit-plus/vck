package at.asitplus.rfc3986uri

import kotlinx.serialization.Serializable

@Serializable
data class Rfc3986Authority(
    val userInfo: Rfc3986UriAuthorityUserInformation?,
    val host: Rfc3986AuthorityHost,
    val rawPort: String?,
) {
    constructor(
        userInfo: Rfc3986UriAuthorityUserInformation?,
        host: Rfc3986AuthorityHost,
        port: ULong,
    ) : this(
        userInfo = userInfo,
        host = host,
        rawPort = port.toString()
    )

    init {
        require(rawPort == null || rawPort.isNotEmpty() && rawPort.all { it in '0'..'9' }) {
            "port must contain decimal digits"
        }
    }

    val port: ULong? = rawPort?.toULongOrNull()

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
                rawPort = portSeparatorIndex?.let {
                    val portString = string.substring(portSeparatorIndex + 1)
                    portString.ifEmpty { null }
                }
            )
        }
    }

    fun toString(includeSensitiveInformation: Boolean) = listOfNotNull(
        userInfo?.toString(includeSensitiveInformation)?.let { "$it@" },
        host,
        rawPort?.let { ":$it" }
    ).joinToString("")

    override fun toString() = toString(false)
}
