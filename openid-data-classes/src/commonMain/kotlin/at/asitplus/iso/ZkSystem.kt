package at.asitplus.iso

/**
 * Represents a configuration and metadata abstraction for a Zero-Knowledge proving system
 * used in ISO mDoc presentation requests
 * (e.g., via OpenID4VP+DCQL or native ISO/IEC 18013-5 Section 10.2.7 ZKP extensions).
 *
 * Implementations are dependent on the underlying request protocol in use.
 */
interface ZkSystem {
    /**
     * A unique identifier for this specific ZK system configuration instance within a request.
     */
    val zkSystemId: String

    /**
     * The name or identifier of the underlying ZK system or proving scheme
     * (e.g., the backend family).
     */
    val system: String

    /**
     * Protocol- or circuit-specific parameters required by the ZK system
     * (e.g., circuit hashes, attribute counts, or versioning parameters).
     */
    val params: Map<String, Any>
}