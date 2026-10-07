package at.asitplus.wallet.sdjwt

import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHashAlgorithm
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.digest

object SignumW3cSubresourceIntegrityMetadataBuilder : W3cSubresourceIntegrityMetadataBuilder {
    override suspend fun build(
        data: ByteArray,
        algorithm: ContentSecurityPolicySourceExpressionHashAlgorithm?
    ): W3cSubresourceIntegrityMetadata {
        val algorithm = algorithm ?: ContentSecurityPolicySourceExpressionHashAlgorithm.sha512
        val data = when (algorithm) {
            ContentSecurityPolicySourceExpressionHashAlgorithm.sha256 -> Digest.SHA256
            ContentSecurityPolicySourceExpressionHashAlgorithm.sha384 -> Digest.SHA384
            ContentSecurityPolicySourceExpressionHashAlgorithm.sha512 -> Digest.SHA512
        }.digest(data)
        return W3cSubresourceIntegrityMetadata(
            hashValue = data,
            algorithm = algorithm,
        )
    }
}
