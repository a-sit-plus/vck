package at.asitplus.wallet.lib.data.rfc.tokenStatusList


//TODO Double check ob jetzt 'type' serialisiert wird
sealed class RevocationList {
    abstract val kind: Kind

    /**
     * Generics really do not work well for our use-case as we need to, for instance in
     * [at.asitplus.wallet.lib.agent.StatusListAgent], define at runtime which kind of
     * [RevocationList] we want to issue. This would require inline+reified generics and these
     * do not play nice with interfaces such as [at.asitplus.wallet.lib.agent.StatusListIssuer].
     */
    enum class Kind{
        STATUS_LIST,
        IDENTIFIER_LIST
    }
}
