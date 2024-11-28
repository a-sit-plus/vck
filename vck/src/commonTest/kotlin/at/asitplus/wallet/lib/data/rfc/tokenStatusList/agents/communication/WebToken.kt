package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication

import at.asitplus.signum.indispensable.cosef.CborWebToken
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import kotlin.jvm.JvmInline

sealed interface WebToken {
    @JvmInline
    value class JsonWebToken(val jwsSigned: JwsSigned<at.asitplus.signum.indispensable.josef.JsonWebToken>) :
        WebToken

    @JvmInline
    value class CborWebToken(val coseSigned: CoseSigned<at.asitplus.signum.indispensable.cosef.CborWebToken>) :
        WebToken
}