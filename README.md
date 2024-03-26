# simple-parser

A very simple (~500 lines) parser for expressions, written in C; just because.

Compiles source expression to stack-based bytecode for a very simple VM

Supports as binary operands

    * /
    + -
    &
    | ^
    << >>
    < <= > >= = !=
    &&
    ||

negation `-` as unary operand

assignments with syntax

    <var> := <expr>

blocks with syntax

    { <expr1>; <expr2>; ... <exprN>[;] }

while loops with syntax

    while ( <test-expr> ) <block>

conditionals with syntax

    if ( <test-expr> ) <block> [ else <block> ]

(a missing else clause will return 0 if the test evaluates to 0)

It's also possible to define functions at the start of an expression with syntax

    def <name>(<parm1>, <parm2>, ..., <parmN>[,]) { <expr1>; <expr2>; ... <exprN>[;] }

those functions can be called with syntax

    <fname>(<arg1>, <arg2>, ..., <argN>[,])

Only data type is IEEE754 double-precision (C `double`); casting to `unsigned` for bitwise operations.

Example:

    ./simple-parser 'def fibo(n){ if (n<2) { 1 } else { fibo(n-1)+fibo(n-2) }} fibo(30)'
