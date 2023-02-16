package at.asitplus.wallet.lib.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * VC spec leaves the representation of a single credential open to implementations.
 * We decided to make a "generic" one, i.e. with custom [name], [value] and [mimeType].
 */
@Serializable
@SerialName("AtomicAttribute")
class AtomicAttributeCredential : CredentialSubject {
    @SerialName("name")
    val name: String

    @SerialName("value")
    val value: String

    @SerialName("mime-type")
    val mimeType: String

    constructor(id: String, name: String, value: String, mimeType: String) : super(id = id) {
        this.name = name
        this.value = value
        this.mimeType = mimeType
    }

    constructor(id: String, name: String, value: String) : this(id, name, value, "application/text")

    override fun toString(): String {
        return "AtomicAttributeCredential(id='$id', name='$name', value='$value', mimeType='$mimeType')"
    }


}