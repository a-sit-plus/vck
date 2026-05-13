package at.asitplus.wallet.sdjwt

data class DelegatingSdJwtTypeMetadataDocumentIntegrityChecker(
    val subresourceIntegrityChecker: W3cSubresourceIntegrityChecker
) : SdJwtTypeMetadataDocumentIntegrityChecker {
    override suspend fun checkIntegrity(
        document: SdJwtTypeMetadataDocument,
        integrityHash: W3cSubresourceIntegrityMetadata,
    ) = subresourceIntegrityChecker.checkIntegrity(
        data = document.originalBytes,
        integrityHash = integrityHash,
    )
}
