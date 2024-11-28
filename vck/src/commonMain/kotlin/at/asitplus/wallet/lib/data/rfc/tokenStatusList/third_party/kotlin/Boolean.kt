package at.asitplus.wallet.lib.data.rfc.tokenStatusList.third_party.kotlin

fun Boolean.ifTrue(block: () -> Unit) {
    if(this) {
        block()
    }
}

fun Boolean.ifFalse(block: () -> Unit) {
    if(!this) {
        block()
    }
}