package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents

interface RelyingParty<ReferencedToken: Any> {
    fun validateReferencedToken(referencedToken: ReferencedToken)

    fun sendStatusListRequest()
}

