package at.asitplus.wallet.lib.data.rfc9110

/**
 *  6.2. Control Data
 *
 * Messages start with control data that describe its primary purpose. Request message control data
 * includes a request method (Section 9), request target (Section 7.1), and protocol version
 * (Section 2.5). Response message control data includes a status code (Section 15), optional
 * reason phrase, and protocol version.
 * In HTTP/1.1 ([HTTP/1.1]) and earlier, control data is sent as the first line of a message. In
 * HTTP/2 ([HTTP/2]) and HTTP/3 ([HTTP/3]), control data is sent as pseudo-header fields with a
 * reserved name prefix (e.g., ":authority"). Every HTTP message has a protocol version. Depending
 * on the version in use, it might be identified within the message explicitly or inferred by the
 * connection over which the message is received. Recipients use that version information to
 * determine limitations or potential for later communication with that sender. When a message is
 * forwarded by an intermediary, the protocol version is updated to reflect the version used by
 * that intermediary. The Via header field (Section 7.6.3) is used to communicate upstream protocol
 * information within a forwarded message. A client SHOULD send a request version equal to the
 * highest version to which the client is conformant and whose major version is no higher than the
 * highest version supported by the server, if this is known. A client MUST NOT send a version to
 * which it is not conformant. A client MAY send a lower request version if it is known that the
 * server incorrectly implements the HTTP specification, but only after the client has attempted at
 * least one normal request and determined from the response status code or header fields
 * (e.g., Server) that the server improperly handles higher request versions. A server SHOULD send
 * a response version equal to the highest version to which the server is conformant that has a
 * major version less than or equal to the one received in the request. A server MUST NOT send a
 * version to which it is not conformant. A server can send a 505 (HTTP Version Not Supported)
 * response if it wishes, for any reason, to refuse service of the client's major protocol version.
 * A recipient that receives a message with a major version number that it implements and a minor
 * version number higher than what it implements SHOULD process the message as if it were in the
 * highest minor version within that major version to which the recipient is conformant. A
 * recipient can assume that a message with a higher minor version, when sent to a recipient that
 * has not yet indicated support for that higher version, is sufficiently backwards-compatible to
 * be safely processed by any implementation of the same major version.
 */
sealed interface HttpMessageControlData

data class HttpRequestMessageControlData(
    val requestMethod: HttpRequestMethod,
    val requestTarget: HttpRequestTarget,
    /**
     * This is not interesting as long as nobody actually tries to build a http client
     */
    val protocolVersion: HttpProtocolVersion = HttpProtocolVersion,
) : HttpMessageControlData

data class HttpResponseMessageControlData(
    val statusCode: HttpStatusCode,
    val reasonPhrase: String = "",
    /**
     * This is not interesting as long as nobody actually tries to build a http client
     */
    val protocolVersion: HttpProtocolVersion = HttpProtocolVersion,
) : HttpMessageControlData

