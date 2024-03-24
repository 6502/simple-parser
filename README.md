# simple-parser

A very simple (~300 lines) parser for expressions, written in C; just because

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

    { <expr1>; <expr2>; ... <exprn>[;] }

and while loops with syntax

    while ( <test-expr> ) <block>


Only data type is IEEE754 double-precision (C `double`); casting to `unsigned` for bitwise operations.

Example:

    ./simple-parser '{ res := 1; x := 10; while (x > 1) { res := res*x; x := x-1; }; res }'


Compiles source expression to stack-based bytecode for a very simple VM