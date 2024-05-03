package at.asitplus.jsonpath.implementation

import org.antlr.v4.kotlinruntime.ParserRuleContext
import org.antlr.v4.kotlinruntime.Token
import org.antlr.v4.kotlinruntime.ast.Position

internal data class AbstractSyntaxTree<T>(
    val text: String,
    val position: Position?,
    val value: T,
    val children: List<AbstractSyntaxTree<out T>> = listOf(),
) {
    constructor(
        context: ParserRuleContext?,
        value: T,
        children: List<AbstractSyntaxTree<out T>> = listOf(),
    ) : this(
        text = context?.text ?: "",
        position = context?.position,
        value = value,
        children = children,
    )
    constructor(
        token: Token,
        value: T,
        children: List<AbstractSyntaxTree<out T>> = listOf(),
    ) : this(
        text = token.text ?: "",
        position = token.startPoint().let { Position(it, token.endPoint() ?: it) },
        value = value,
        children = children,
    )
}