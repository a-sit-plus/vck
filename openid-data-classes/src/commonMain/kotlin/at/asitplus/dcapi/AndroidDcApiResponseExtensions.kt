package at.asitplus.dcapi

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer

/** Encodes this response for Android's Digital Credentials API integration. */
fun DigitalCredentialInterface.toAndroidDcApiResponseJson(): String =
    joseCompliantSerializer.encodeToString<DigitalCredentialInterface>(this)
