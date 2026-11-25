import Foundation

public extension Data {
    /// Copies this data into Kotlin-owned memory.
    var kotlinByteArray: KotlinByteArray {
        get throws { try ByteArrayBridge.shared.fromData(data: self) }
    }
}

public extension Array where Element == UInt8 {
    var kotlinByteArray: KotlinByteArray {
        get throws { try Data(self).kotlinByteArray }
    }
}

public extension KotlinByteArray {
    /// Copies these bytes into Swift-owned memory.
    var data: Data { ByteArrayBridge.shared.toData(bytes: self) }
    var bytes: [UInt8] { Array(data) }
}

/// Unwraps without calling Kotlin's unannotated, potentially fatal getOrThrow export.
/// Always returns an optional: Objective-C export loses the nullability of Kotlin's T.
/// Use `result.swiftResult(as: String.self).get()` for a checked non-optional value,
/// or request `String?.self` to allow a successful null.
public func kotlinValue<T>(_ result: KmmResult<T>) throws -> T? {
    if let cause = result.exceptionOrNull() { try SwiftErrorBridge.shared.rethrow(cause: cause) }
    return result.getOrNull()
}

public extension Error {
    /// The Kotlin exception behind this error, if Kotlin threw it.
    var kotlinThrowable: KotlinThrowable? { (self as NSError).userInfo["KotlinException"] as? KotlinThrowable }

    /// The OAuth 2.0 error from the issuer or authorization server, also as a cause of the Kotlin exception.
    /// Read its `error` and `errorDescription`: SKIE renames the subclasses' own `description` to `description_`.
    var oauth2Exception: OAuth2Exception? {
        var current = kotlinThrowable
        for _ in 0..<16 { // Bounded, in case of a cyclic cause chain.
            guard let throwable = current else { return nil }
            if let exception = throwable as? OAuth2Exception { return exception }
            current = throwable.cause
        }
        return nil
    }
}

@objc public protocol KmmResultSwiftConvertible {
    var erasedKmmResult: KmmResult<AnyObject> { get }
}

extension KmmResult: KmmResultSwiftConvertible {
    // Objective-C generics are erased; the protocol lets Swift extend the result without capturing T.
    public var erasedKmmResult: KmmResult<AnyObject> { (self as AnyObject) as! KmmResult<AnyObject> }
}

public extension KmmResultSwiftConvertible {
    /// Converts to Swift's Result, checking the requested success type (including bridged arrays).
    func swiftResult<Value>(as type: Value.Type) -> Result<Value, Error> {
        let result = erasedKmmResult
        return Result { try callbackArgument(kotlinValue(result), as: type) }
    }
}

// The raw invoke exports only allow CancellationException; these calls export all errors.
@available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
public extension KotlinSuspendFunction0 {
    func callAsFunction() async throws -> Any? {
        try await SuspendFunctionBridge.shared.call0(function: self)
    }
}

@available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
public extension KotlinSuspendFunction1 {
    func callAsFunction(_ argument: Any?) async throws -> Any? {
        try await SuspendFunctionBridge.shared.call1(function: self, argument: argument)
    }
}

@available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
public extension KotlinSuspendFunction2 {
    func callAsFunction(_ first: Any?, _ second: Any?) async throws -> Any? {
        try await SuspendFunctionBridge.shared.call2(function: self, first: first, second: second)
    }
}

func callbackArgument<T>(_ value: Any?, as type: T.Type) throws -> T {
    guard let typed = value as? T else {
        let received = value.map { String(describing: Swift.type(of: $0)) } ?? "nil"
        throw NSError(
            domain: "VckIos.SwiftSuspendFunction", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Expected \(T.self), received \(received)"]
        )
    }
    return typed
}

private protocol OptionalCallbackResult {
    var unwrapped: Any? { get }
}

extension Optional: OptionalCallbackResult {
    fileprivate var unwrapped: Any? {
        switch self {
        case .none: return nil
        case .some(let value): return callbackResult(value)
        }
    }
}

private func callbackResult<T>(_ value: T) -> Any? {
    if let optional = value as? OptionalCallbackResult { return optional.unwrapped }
    if value is Void { return KotlinUnit() }
    return value
}

@available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
private func runCallback<T>(_ body: () async throws -> T) async throws -> Any? {
    do { return callbackResult(try await body()) }
    catch is CancellationError {
        // Preserve cancellation as Kotlin's CancellationException rather than ObjCErrorException.
        try SwiftErrorBridge.shared.cancellation()
        return nil // The Kotlin helper always throws.
    }
}

// ponytail: exported protocol implementations cannot propagate Kotlin cancellation into
// Swift async closures. Use a cancellable Kotlin callback bridge if that is required.
/// Wraps a Swift async closure for APIs expecting KotlinSuspendFunction0.
/// Kotlin cancellation does not cancel the Swift closure.
@available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
public final class SwiftSuspendFunction0<Output>: NSObject, KotlinSuspendFunction0 {
    private let body: () async throws -> Output

    public init(_ body: @escaping () async throws -> Output) { self.body = body }

    public func __invoke() async throws -> Any? { try await runCallback(body) }
}

/// Wraps a typed Swift async closure for APIs expecting KotlinSuspendFunction1.
/// Kotlin cancellation does not cancel the Swift closure.
@available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
public final class SwiftSuspendFunction1<Input, Output>: NSObject, KotlinSuspendFunction1 {
    private let body: (Input) async throws -> Output

    public init(_ body: @escaping (Input) async throws -> Output) { self.body = body }

    public func __invoke(p1: Any?) async throws -> Any? {
        try await runCallback { try await self.body(callbackArgument(p1, as: Input.self)) }
    }
}

/// Wraps a typed Swift async closure for APIs expecting KotlinSuspendFunction2.
/// Kotlin cancellation does not cancel the Swift closure.
@available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
public final class SwiftSuspendFunction2<Input1, Input2, Output>: NSObject, KotlinSuspendFunction2 {
    private let body: (Input1, Input2) async throws -> Output

    public init(_ body: @escaping (Input1, Input2) async throws -> Output) { self.body = body }

    public func __invoke(p1: Any?, p2: Any?) async throws -> Any? {
        try await runCallback {
            try await self.body(callbackArgument(p1, as: Input1.self), callbackArgument(p2, as: Input2.self))
        }
    }
}
