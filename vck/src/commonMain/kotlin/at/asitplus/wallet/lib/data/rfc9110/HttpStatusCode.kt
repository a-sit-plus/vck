package at.asitplus.wallet.lib.data.rfc9110

import kotlin.jvm.JvmInline

/**
 *  15. Status Codes
 *
 * The status code of a response is a three-digit integer code that describes the result of the
 * request and the semantics of the response, including whether the request was successful and what
 * content is enclosed (if any). All valid status codes are within the range of 100 to 599,
 * inclusive.
 * The first digit of the status code defines the class of response. The last two digits do not
 * have any categorization role. There are five values for the first digit:
 * 1xx (Informational): The request was received, continuing process
 * 2xx (Successful): The request was successfully received, understood, and accepted
 * 3xx (Redirection): Further action needs to be taken in order to complete the request
 * 4xx (Client Error): The request contains bad syntax or cannot be fulfilled
 * 5xx (Server Error): The server failed to fulfill an apparently valid request
 *
 * HTTP status codes are extensible. A client is not required to understand the meaning of all
 * registered status codes, though such understanding is obviously desirable. However, a client
 * MUST understand the class of any status code, as indicated by the first digit, and treat an
 * unrecognized status code as being equivalent to the x00 status code of that class. For example,
 * if a client receives an unrecognized status code of 471, it can see from the first digit that
 * there was something wrong with its request and treat the response as if it had received a 400
 * (Bad Request) status code. The response message will usually contain a representation that
 * explains the status. Values outside the range 100..599 are invalid. Implementations often use
 * three-digit integer values outside of that range (i.e., 600..999) for internal communication of
 * non-HTTP status (e.g., library errors). A client that receives a response with an invalid status
 * code SHOULD process the response as if it had a 5xx (Server Error) status code.
 *
 * A single request can have multiple associated responses: zero or more "interim" (non-final)
 * responses with status codes in the "informational" (1xx) range, followed by exactly one "final"
 * response with a status code in one of the other ranges.
 */
@JvmInline
value class HttpStatusCode(val value: Int) {
    init {
        validate(value)
    }

    val isInformational: Boolean
        get() = value in 100..199
    val isSuccessful: Boolean
        get() = value in 200..299
    val isRedirection: Boolean
        get() = value in 300..399
    val isClientError: Boolean
        get() = value in 400..499
    val isServerError: Boolean
        get() = value in 500..599

    companion object {
        fun validate(value: Int) = value in 100..599

        val OK = HttpStatusCode(Specification.OK)
    }

    object Specification {
        const val OK = 200
    }
}