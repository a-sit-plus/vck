// 1. converted from abnf using tool:
//      - http://www.robertpinchbeck.com/abnf_to_antlr/Default.aspx
// 2. manually resolved lexer ambiguities
parser grammar JsonPathParser;

options { tokenVocab=JsonPathLexer; }

jsonpath_query      : rootIdentifier segments;
segments            : (ws segment)*;
segment             : bracketed_selection | SHORTHAND_SELECTOR shorthand_segment | DESCENDANT_SELECTOR descendant_segment;
shorthand_segment   : wildcardSelector | memberNameShorthand;
descendant_segment  : bracketed_selection |
                            wildcardSelector |
                            memberNameShorthand;

bracketed_selection : SQUARE_BRACKET_OPEN ws selector (ws COMMA ws selector)* ws SQUARE_BRACKET_CLOSE;
selector            : name_selector |
                      wildcardSelector |
                      slice_selector |
                      index_selector |
                      filter_selector;
name_selector       : stringLiteral;


index_selector      : INT;                        // decimal integer

slice_selector      : (start ws)? COLON ws (end ws)? (COLON (ws step )?)?;

start               : INT;       // included in selection
end                 : INT;       // not included in selection
step                : INT;       // default: 1

// used in filter, but executed in normal mode
filter_query        : rel_query | jsonpath_query;
rel_query           : CURRENT_NODE_IDENTIFIER segments;

singular_query      : rel_singular_query | abs_singular_query;
rel_singular_query  : CURRENT_NODE_IDENTIFIER singular_query_segments;
abs_singular_query  : rootIdentifier singular_query_segments;
singular_query_segments : (ws (name_segment | index_segment))*;
name_segment        : (SQUARE_BRACKET_OPEN name_selector SQUARE_BRACKET_CLOSE) |
                      (SHORTHAND_SELECTOR memberNameShorthand);
index_segment       : SQUARE_BRACKET_OPEN index_selector SQUARE_BRACKET_CLOSE;


filter_selector     : QUESTIONMARK ws logical_expr;
logical_expr        : logical_or_expr;
logical_or_expr     : logical_and_expr (ws LOGICAL_OR_OP ws logical_and_expr)*;
                        // disjunction
                        // binds less tightly than conjunction
logical_and_expr    : basic_expr (ws LOGICAL_AND_OP ws basic_expr)*;
                        // conjunction
                        // binds more tightly than disjunction

basic_expr          : paren_expr |
                      comparison_expr |
                      test_expr;

paren_expr          : (LOGICAL_NOT_OP ws)? BRACKET_OPEN ws logical_expr ws BRACKET_CLOSE;
                                        // parenthesized expression
test_expr           : (LOGICAL_NOT_OP ws)?
                      (filter_query | // existence/non-existence
                       function_expr); // LogicalType or NodesType
comparison_expr     : comparable ws comparisonOp ws comparable;
literal             : number | stringLiteral |
                      true | false | null;
comparable          : literal |
                      singular_query | // singular query value
                      function_expr;    // ValueType

function_expr       : FUNCTION_NAME BRACKET_OPEN ws (function_argument
                         (ws COMMA ws function_argument)*)? ws BRACKET_CLOSE;
function_argument   : literal |
                      filter_query | // (includes singular-query)
                      function_expr |
                      logical_expr;



rootIdentifier: ROOT_IDENTIFIER;
ws: BLANK*;

wildcardSelector: WILDCARD_SELECTOR;
memberNameShorthand: MEMBER_NAME_SHORTHAND;

number: NUMBER | INT; // integer is matched before number, but it is also a valid number literal
stringLiteral: STRING_LITERAL;
true: TRUE;
false: FALSE;
null: NULL;

comparisonOp
    : COMPARISON_OP_EQUALS | COMPARISON_OP_NOT_EQUALS
    | COMPARISON_OP_SMALLER_THAN | COMPARISON_OP_GREATER_THAN
    | COMPARISON_OP_SMALLER_THAN_OR_EQUALS | COMPARISON_OP_GREATER_THAN_OR_EQUALS
    ;