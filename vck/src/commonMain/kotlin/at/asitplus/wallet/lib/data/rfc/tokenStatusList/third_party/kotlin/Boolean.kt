package at.asitplus.wallet.lib.data.rfc.tokenStatusList.third_party.kotlin

fun <T> Boolean.ifTrue(block: () -> T) {
    if(this) {
        block()
    }
}

fun <T> Boolean.ifFalse(block: () -> T) {
    if(!this) {
        block()
    }
}