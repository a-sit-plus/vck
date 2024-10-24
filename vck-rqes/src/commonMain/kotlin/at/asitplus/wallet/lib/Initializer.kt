package at.asitplus.wallet.lib

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationRequestParametersFrom
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.rqes.SignatureRequestParameters
import at.asitplus.rqes.SignatureRequestParametersFrom
import at.asitplus.rqes.rdcJsonSerializer
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.serializerModuleCollection
import at.asitplus.wallet.lib.oidc.OidcSiopWallet
import at.asitplus.wallet.lib.oidc.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidc.helper.RequestParser
import at.asitplus.wallet.lib.oidc.jsonSerializer
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.json
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.modules.overwriteWith


object Initializer {
    fun initRqesModule() {
        serializerModuleCollection = serializerModuleCollection.overwriteWith(rdcJsonSerializer.serializersModule)
    }
}

