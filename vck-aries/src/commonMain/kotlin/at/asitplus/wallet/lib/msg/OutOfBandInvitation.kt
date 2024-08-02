package at.asitplus.wallet.lib.msg

import at.asitplus.wallet.lib.aries.jsonSerializer
import at.asitplus.wallet.lib.data.SchemaIndex
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * From [ARIES RFC 0434](https://github.com/hyperledger/aries-rfcs/blob/main/features/0434-outofband)
 */
@Serializable
@SerialName(SchemaIndex.MSG_OOB_INVITATION)
class OutOfBandInvitation : JsonWebMessage {

    @SerialName("body")
    val body: OutOfBandInvitationBody

    constructor(body: OutOfBandInvitationBody) : super(SchemaIndex.MSG_OOB_INVITATION) {
        this.body = body
    }

    override fun serialize() = jsonSerializer.encodeToString(this)

    override fun toString(): String {
        return "OutOfBandInvitation(body=$body)"
    }

}