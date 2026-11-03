package at.asitplus.wallet.lib

import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid


fun uuid4() = @OptIn(ExperimentalUuidApi::class) Uuid.random().toString()
