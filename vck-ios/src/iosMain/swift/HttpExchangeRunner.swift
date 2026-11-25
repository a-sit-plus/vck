import Foundation

@available(iOS 15, macOS 12, watchOS 8, tvOS 15, *)
public extension HttpExchange {
    /// Sends the requests of this exchange, e.g. from `OpenId4VpProtocolClient`, with `session`, and returns its
    /// result as `type`. Redirects are not followed: VC-K treats them as errors, as its ktor clients do.
    func run<T>(as type: T.Type, session: URLSession = .shared) async throws -> T {
        let transport = URLSessionTransport(session: session)
        var response: ReceivedHttpResponse?
        while true {
            guard let step = try kotlinValue(try await next(response: response)) else {
                throw NSError(domain: "VckIos.HttpExchange", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "Exchange returned no step"])
            }
            switch onEnum(of: step) {
            case .done(let done):
                return try callbackArgument(done.value, as: type)
            case .send(let send):
                response = try await transport.send(HttpExchangeBridge.shared.request(request: send.request))
            }
        }
    }
}

/// Sends VC-K's HTTP requests with `URLSession`, e.g. for `HttpExchange.run`. Redirects are not followed.
/// Kotlin cancellation does not cancel a request already sent.
@available(iOS 15, macOS 12, watchOS 8, tvOS 15, *)
public final class URLSessionTransport: NSObject, HttpTransport {
    private let session: URLSession

    public init(session: URLSession = .shared) { self.session = session }

    public func __send(request: SwiftHttpRequest) async throws -> ReceivedHttpResponse {
        do { return try await send(request) }
        catch is CancellationError {
            try SwiftErrorBridge.shared.cancellation()
            throw CancellationError() // The Kotlin helper always throws.
        }
    }

    func send(_ request: SwiftHttpRequest) async throws -> ReceivedHttpResponse {
        guard let url = URL(string: request.url) else { throw URLError(.badURL) }
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = request.method
        request.headers.forEach { urlRequest.setValue($0.value, forHTTPHeaderField: $0.key) }
        if let contentType = request.contentType {
            urlRequest.setValue(contentType, forHTTPHeaderField: "Content-Type")
        }
        urlRequest.httpBody = request.body
        let (data, urlResponse) = try await session.data(for: urlRequest, delegate: NoRedirects.shared)
        guard let http = urlResponse as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        let headers = http.allHeaderFields.reduce(into: [String: String]()) { headers, field in
            if let name = field.key as? String { headers[name] = "\(field.value)" }
        }
        return HttpExchangeBridge.shared.response(
            status: Int32(http.statusCode), headers: headers, body: String(decoding: data, as: UTF8.self)
        )
    }
}

private final class NoRedirects: NSObject, URLSessionTaskDelegate {
    static let shared = NoRedirects()

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? { nil }
}
