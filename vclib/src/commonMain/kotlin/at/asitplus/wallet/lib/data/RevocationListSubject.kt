package at.asitplus.wallet.lib.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Credential representing a [W3C RevocationList 2020](https://w3c-ccg.github.io/vc-status-rl-2020/) credential,
 * i.e. the [encodedList] contains a compressed bitset representing revoked credentials.
 */
@Serializable
@SerialName(VcDataModelConstants.REVOCATION_LIST_2020)
class RevocationListSubject : CredentialSubject {

    @SerialName("encodedList")
    val encodedList: String

    constructor(id: String, encodedList: String) : super(id = id) {
        this.encodedList = encodedList
    }

    override fun toString(): String {
        return "RevocationListSubject(id='$id', encodedList='$encodedList')"
    }

}