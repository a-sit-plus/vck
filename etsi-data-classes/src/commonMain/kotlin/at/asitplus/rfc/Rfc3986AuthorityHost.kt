package at.asitplus.rfc

/**
 * We don't really want to go further down the rabbit hole.
 */
sealed interface Rfc3986AuthorityHost {
    companion object {
        operator fun invoke(string: String): Rfc3986AuthorityHost {
            return if(string.startsWith("[")) {
                val trimmed = string.trimStart('[').trimEnd(']')
                if(trimmed.startsWith("v")) {
                    Rfc3986AuthorityHostIPvFuture(string)
                } else {
                    Rfc3986AuthorityHostIPv6(trimmed)
                }
            } else {
                try {
                    Rfc3986AuthorityHostIPv4(string)
                } catch (it: Throwable) {
                    Rfc3986AuthorityHostRegisteredName(string)
                }
            }
        }
    }
}