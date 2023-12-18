package at.asitplus.wallet.lib.data

object AriesGoalCodeParser {
    private val mapGoalCodeToScheme = mutableMapOf<String, ConstantIndex.CredentialScheme>()

    init {
        registerGoalCode(ConstantIndex.AtomicAttribute2023)
        registerGoalCode(ConstantIndex.MobileDrivingLicence2023)
    }

    fun parseGoalCode(goalCode: String) = when (goalCode) {
        in mapGoalCodeToScheme -> mapGoalCodeToScheme[goalCode]
        else -> null
    }

    internal fun registerGoalCode(scheme: ConstantIndex.CredentialScheme) {
        mapGoalCodeToScheme += "issue-vc-${getAriesName(scheme)}" to scheme
        mapGoalCodeToScheme += "request-proof-${getAriesName(scheme)}" to scheme
    }

    fun getAriesName(credentialScheme: ConstantIndex.CredentialScheme): String {
        val builder = StringBuilder()
        credentialScheme.vcType.forEachIndexed { index, char ->
            if (char.isUpperCase() && index > 0) builder.append("-").append(char.lowercaseChar())
            else builder.append(char)
        }
        return builder.toString()
    }
}
