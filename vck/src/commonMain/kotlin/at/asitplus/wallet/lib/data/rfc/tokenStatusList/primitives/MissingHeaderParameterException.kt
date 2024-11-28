package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

class MissingHeaderParameterException(val headerParameterName: String) : IllegalStateException("Missing header parameter `$headerParameterName`")