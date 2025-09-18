package at.asitplus.dcapi.request

import kotlinx.serialization.Serializable

/**
 * Abstract base class for requests received via the Digital Credentials API.
 */
@Serializable
sealed class DCAPIRequest