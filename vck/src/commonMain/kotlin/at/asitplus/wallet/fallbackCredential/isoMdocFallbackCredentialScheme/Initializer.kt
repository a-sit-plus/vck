package at.asitplus.wallet.fallbackCredential.isoMdocFallbackCredentialScheme
import at.asitplus.wallet.lib.LibraryInitializer

object Initializer {

    /**
     * A reference to this class is enough to trigger the init block
     */
    init {
        initWithVCK()
    }

    /**
     * This has to be called first, before anything, to load the
     * relevant classes' serializer's of this library into the base implementations of VC-K
     */
    fun initWithVCK() {
        LibraryInitializer.registerExtensionLibrary(
            credentialScheme = IsoMdocFallbackCredentialScheme
        )
    }
}