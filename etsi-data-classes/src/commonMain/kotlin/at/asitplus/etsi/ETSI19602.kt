package at.asitplus.etsi

object ETSI19602 {

    const val BASE_FETCH_URL: String = "https://acceptance.trust.tech.ec.europa.eu/lists/eudiw"

    /*
    * PID Provider's LoTE
    */
    const val EU_PID_PROVIDERS_FETCH_URL: String = "$BASE_FETCH_URL/pid-providers.json"
    const val EU_PID_PROVIDERS_SCHEME_TYPE: String = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"
    const val EU_PID_PROVIDERS_STATUS_DETERMINATION_APPROACH: String = "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU"
    const val EU_PID_PROVIDERS_SCHEME_COMMUNITY_RULES: String = "http://uri.etsi.org/19602/PIDProviders/schemerules/EU"
    const val EU_PID_PROVIDERS_SVC_TYPE_ISSUANCE: String = "http://uri.etsi.org/19602/SvcType/PID/Issuance"
    const val EU_PID_PROVIDERS_SVC_TYPE_REVOCATION: String = "http://uri.etsi.org/19602/SvcType/PID/Revocation"

    /*
    * EU Wallet Provider's LoTE
    */
    const val EU_WALLET_PROVIDERS_FETCH_URL: String = "$BASE_FETCH_URL/wallet-providers.json"
    const val EU_WALLET_PROVIDERS_SCHEME_TYPE: String = "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList"
    const val EU_WALLET_PROVIDERS_STATUS_DETERMINATION_APPROACH: String = "http://uri.etsi.org/19602/WalletProvidersList/StatusDetn/EU"
    const val EU_WALLET_PROVIDERS_SCHEME_COMMUNITY_RULES: String = "http://uri.etsi.org/19602/WalletProvidersList/schemerules/EU"
    const val EU_WALLET_PROVIDERS_SVC_TYPE_ISSUANCE: String = "http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance"
    const val EU_WALLET_PROVIDERS_SVC_TYPE_REVOCATION: String = "http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation"

    /*
    * EU WRPAC LoTE
    */
    const val EU_WRPAC_PROVIDERS_FETCH_URL: String = "$BASE_FETCH_URL/wrpac-providers.json"
    const val EU_WRPAC_PROVIDERS_SCHEME_TYPE: String = "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList"
    const val EU_WRPAC_PROVIDERS_STATUS_DETERMINATION_APPROACH: String = "http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU"
    const val EU_WRPAC_PROVIDERS_SCHEME_COMMUNITY_RULES: String = "http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU"
    const val EU_WRPAC_PROVIDERS_SVC_TYPE_ISSUANCE: String = "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance"
    const val EU_WRPAC_PROVIDERS_SVC_TYPE_REVOCATION: String = "http://uri.etsi.org/19602/SvcType/WRPAC/Revocation"


    /*
    * EU PUB EAA Provider's LoTE
    */
    const val EU_PUB_EAA_PROVIDERS_FETCH_URL: String = "$BASE_FETCH_URL/pub-eaa-providers.json"
    const val EU_PUB_EAA_PROVIDERS_SCHEME_TYPE: String = "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList"
    const val EU_PUB_EAA_PROVIDERS_STATUS_DETERMINATION_APPROACH: String = "http://uri.etsi.org/19602/PubEAAProvidersList/StatusDetn/EU"
    const val EU_PUB_EAA_PROVIDERS_SCHEME_COMMUNITY_RULES: String = "http://uri.etsi.org/19602/PubEAAProvidersList/schemerules/EU"
    const val EU_PUB_EAA_PROVIDERS_SVC_TYPE_ISSUANCE: String = "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance"
    const val EU_PUB_EAA_PROVIDERS_SVC_TYPE_REVOCATION: String = "http://uri.etsi.org/19602/SvcType/PubEAA/Revocation"

    /*
    * EU mDL Provider's LoTE
    */
    const val EU_mDL_PROVIDERS_FETCH_URL: String = "$BASE_FETCH_URL/mdl-providers.json"
    const val EU_mDL_PROVIDERS_SCHEME_TYPE: String = "http://trust.ec.europa.eu/lists/mDL/mDLProvidersListType"
    const val EU_mDL_PROVIDERS_STATUS_DETERMINATION_APPROACH: String = "http://trust.ec.europa.eu/lists/mDL/mDLProvidersListStatusDetn"
    const val EU_mDL_PROVIDERS_SCHEME_COMMUNITY_RULES: String = "http://trust.ec.europa.eu/lists/mDL/schemerules"
    const val EU_mDL_PROVIDERS_SVC_TYPE_ISSUANCE: String = "http://trust.ec.europa.eu/lists/mDL/SvcType/Issuance"
    const val EU_mDL_PROVIDERS_SVC_TYPE_REVOCATION: String = "http://trust.ec.europa.eu/lists/mDL/SvcType/Revocation"
}