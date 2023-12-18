package at.asitplus.wallet.lib.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * VC spec leaves the representation of a single credential open to implementations.
 * We decided to make a "generic" one, i.e. with custom [name], [value] and [mimeType].
 */
@Serializable
@SerialName("AtomicAttribute2023")
data class AtomicAttribute2023(
    override val id: String,

    @SerialName("name")
    val name: String,

    @SerialName("value")
    val value: String,

    @SerialName("mime-type")
    val mimeType: String,
) : CredentialSubject() {

    constructor(id: String, name: String, value: String) : this(id, name, value, "application/text")

}