import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import at.asitplus.wallet.eupid.EU_PID_METADATA_URL
import at.asitplus.wallet.eupid.EuPidItemValueSerializerMap
import at.asitplus.wallet.eupid.EuPidJsonValueEncoder
import at.asitplus.wallet.eupid.EuPidMetadataDocument
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_METADATA_URL
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtMetadataDocument
import at.asitplus.wallet.lib.LibraryInitializer
import at.asitplus.wallet.lib.data.StaticCredentialMetadataRegistry
import at.asitplus.wallet.mdl.MDL_METADATA_URL
import at.asitplus.wallet.mdl.MobileDrivingLicenceItemValueSerializerMap
import at.asitplus.wallet.mdl.MobileDrivingLicenceJsonValueEncoder
import at.asitplus.wallet.mdl.MobileDrivingLicenceMetadataDocument
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocumentRegistry
import de.infix.testBalloon.framework.core.TestSession
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier

class TestConfig : TestSession(
    testConfig = DefaultConfiguration.apply { MatrixTestDefaults { execution = ExecutionMode.Concurrent(8) } }
) {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())

        LibraryInitializer.registerCredentialMetadataRegistry(
            StaticCredentialMetadataRegistry(
                documentRegistry = SdJwtTypeMetadataDocumentRegistry(
                    EuPidSdJwtMetadataDocument,
                    EuPidMetadataDocument,
                    MobileDrivingLicenceMetadataDocument,
                ),
                documentUrls = mapOf(
                    EuPidSdJwtMetadataDocument.first to EU_PID_SD_JWT_METADATA_URL,
                    EuPidMetadataDocument.first to EU_PID_METADATA_URL,
                    MobileDrivingLicenceMetadataDocument.first to MDL_METADATA_URL,
                )
            )
        )

        LibraryInitializer.registerCredentialSerializers(
            jsonValueEncoder = MobileDrivingLicenceJsonValueEncoder,
            itemValueSerializerMap = MobileDrivingLicenceItemValueSerializerMap
        )
        LibraryInitializer.registerCredentialSerializers(
            jsonValueEncoder = EuPidJsonValueEncoder,
            itemValueSerializerMap = EuPidItemValueSerializerMap,
        )
    }
}

