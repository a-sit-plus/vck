package at.asitplus.dcapi

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.encodeToByteArray

/** Encodes this response for Apple's ISO 18013 mobile document response API. */
fun DigitalCredentialInterface.toIosIsoMdocResponseBytes(): ByteArray {
    val isoMdocResponse = this as? IsoMdocResponse
        ?: throw IllegalArgumentException("iOS mobile document responses require ISO 18013-7 Annex C")
    return coseCompliantSerializer.encodeToByteArray(isoMdocResponse.data.response)
}
