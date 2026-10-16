package at.asitplus.etsi.relyingParty

object WrpConstants {
    /** OID of the WRPRC certificate policy defined in ETSI TS 119 475 V1.2.1, clause 6.1.3. */
    const val POLICY_IDENTIFIER = "0.4.0.19475.3.1"

    /** Entitlement of a provider of person identification data (ETSI TS 119 475 V1.2.1, A.2). */
    const val ENTITLEMENT_PID_PROVIDER = "https://uri.etsi.org/19475/Entitlement/PID_Provider"

    /** Entitlement of a QTSP issuing qualified electronic attestations of attributes (A.2). */
    const val ENTITLEMENT_QEAA_PROVIDER = "https://uri.etsi.org/19475/Entitlement/QEAA_Provider"

    /** Entitlement of a TSP issuing non-qualified electronic attestations of attributes (A.2). */
    const val ENTITLEMENT_NON_Q_EAA_PROVIDER = "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"

    /** Entitlement of a public sector body issuing electronic attestations of attributes (A.2). */
    const val ENTITLEMENT_PUB_EAA_PROVIDER = "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider"

    /** The entitlements of providers of attestations to wallets, i.e. of credential issuers (4.2, Table 8). */
    val ATTESTATION_PROVIDER_ENTITLEMENTS = setOf(
        ENTITLEMENT_PID_PROVIDER,
        ENTITLEMENT_QEAA_PROVIDER,
        ENTITLEMENT_NON_Q_EAA_PROVIDER,
        ENTITLEMENT_PUB_EAA_PROVIDER,
    )
}
