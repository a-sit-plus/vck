package at.asitplus.wallet.lib.data.rfc9110

/**
 *  6. Message Abstraction
 *
 * Each major version of HTTP defines its own syntax for communicating messages. This section
 * defines an abstract data type for HTTP messages based on a generalization of those message
 * characteristics, common structure, and capacity for conveying semantics. This abstraction is
 * used to define requirements on senders and recipients that are independent of the HTTP version,
 * such that a message in one version can be relayed through other versions without changing its
 * meaning.
 * A "message" consists of the following:
 * control data to describe and route the message,
 * a headers lookup table of name/value pairs for extending that control data and conveying
 * additional information about the sender, message, content, or context,a potentially unbounded
 * stream of content, anda trailers lookup table of name/value pairs for communicating information
 * obtained while sending the content. Framing and control data is sent first, followed by a header
 * section containing fields for the headers table. When a message includes content, the content is
 * sent after the header section, potentially followed by a trailer section that might contain
 * fields for the trailers table. Messages are expected to be processed as a stream, wherein the
 * purpose of that stream and its continued processing is revealed while being read. Hence, control
 * data describes what the recipient needs to know immediately, header fields describe what needs
 * to be known before receiving content, the content (when present) presumably contains what the
 * recipient wants or needs to fulfill the message semantics, and trailer fields provide optional
 * metadata that was unknown prior to sending the content. Messages are intended to be
 * "self-descriptive": everything a recipient needs to know about the message can be determined by
 * looking at the message itself, after decoding or reconstituting parts that have been compressed
 * or elided in transit, without requiring an understanding of the sender's current application
 * state (established via prior messages). However, a client MUST retain knowledge of the request
 * when parsing, interpreting, or caching a corresponding response. For example, responses to the
 * HEAD method look just like the beginning of a response to GET but cannot be parsed in the same
 * manner. Note that this message abstraction is a generalization across many versions of HTTP,
 * including features that might not be found in some versions. For example, trailers were
 * introduced within the HTTP/1.1 chunked transfer coding as a trailer section after the content.
 * An equivalent feature is present in HTTP/2 and HTTP/3 within the header block that terminates
 * each stream.
 *
 * Note: All fields here are nullable, allowing decision delegation to an actual client/server
 * implementation.
 */
sealed interface HttpMessage {
    val controlData: HttpMessageControlData?
    val headers: List<HttpFieldLine>?
    val content: ByteArray?
    val trailers: List<HttpFieldLine>?
}

data class HttpRequestMessage(
    override val controlData: HttpRequestMessageControlData? = null,
    override val headers: List<HttpFieldLine>? = null,
    override val content: ByteArray? = null,
    override val trailers: List<HttpFieldLine>? = null,
) : HttpMessage {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as HttpRequestMessage

        if (controlData != other.controlData) return false
        if (headers != other.headers) return false
        if (!content.contentEquals(other.content)) return false
        if (trailers != other.trailers) return false

        return true
    }

    override fun hashCode(): Int {
        var result = controlData.hashCode()
        result = 31 * result + headers.hashCode()
        result = 31 * result + content.contentHashCode()
        result = 31 * result + trailers.hashCode()
        return result
    }
}

/**
 * @param content: The raw octet string that has been received, without any decoding performed
 */
data class HttpResponseMessage(
    override val controlData: HttpResponseMessageControlData? = null,
    override val headers: List<HttpFieldLine>? = null,
    override val content: ByteArray? = null,
    override val trailers: List<HttpFieldLine>? = null,
) : HttpMessage {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as HttpResponseMessage

        if (controlData != other.controlData) return false
        if (headers != other.headers) return false
        if (!content.contentEquals(other.content)) return false
        if (trailers != other.trailers) return false

        return true
    }

    override fun hashCode(): Int {
        var result = controlData.hashCode()
        result = 31 * result + headers.hashCode()
        result = 31 * result + content.contentHashCode()
        result = 31 * result + trailers.hashCode()
        return result
    }
}