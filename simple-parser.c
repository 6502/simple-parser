#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>

void error(const char *msg) {
    fprintf(stderr, "Fatal error: %s\n", msg);
    exit(1);
}

void *mem_alloc(int size) {
    void *p = malloc(size); if (!p) error("Out of memory");
    return p;
}

void *mem_realloc(void *p, int size) {
    p = realloc(p, size); if (!p) error("Out of memory");
    return p;
}

void mem_dealloc(void *p) {
    if (p) free(p);
}

struct TExpr;

typedef struct TVMContext {
    struct TExpr *expr;
    double *sp;
    const unsigned char *ip;
} VMContext;

#define FETCH(vm_, T_) ({ T_ x_; memcpy(&x_, (vm_)->ip, sizeof(x_)); (vm_)->ip += sizeof(x_); x_; })

typedef void (*Opcode)(VMContext *vm);

typedef struct TExpr {
    char **var_names;
    double *var_values;
    int var_size, var_alloc;
    unsigned char *code; int code_size, code_alloc;
    int stack_size;
} Expr;

static Expr *allocate_expression() {
    Expr *e = mem_alloc(sizeof(Expr));
    e->var_names = mem_alloc(sizeof(char *)*10);
    e->var_values = mem_alloc(sizeof(char *)*10);
    e->var_size = 0; e->var_alloc = 10;
    e->code = mem_alloc(100);
    e->code_size = 0; e->code_alloc = 100;
    e->stack_size = 0;
    return e;
}

void emit_bytes(Expr *E, void *p, int size) {
    if (E->code_size + size > E->code_alloc) {
        int newalloc = E->code_alloc * 2;
        if (E->code_size + size > newalloc) newalloc = E->code_size + size;
        E->code = mem_realloc(E->code, newalloc);
        E->code_alloc = newalloc;
    }
    memcpy(E->code + E->code_size, p, size);
    E->code_size += size;
}

void emit(Expr *E, Opcode op) {
    emit_bytes(E, &op, sizeof(op));
}

void deallocate_expression(Expr *e) {
    if (e) {
        for (int i=0; i<e->var_size; i++) mem_dealloc(e->var_names[i]);
        mem_dealloc(e->var_names);
        mem_dealloc(e->var_values);
        mem_dealloc(e->code);
        mem_dealloc(e);
    }
}

void skip_spaces(const char **s) {
    for(;;) {
        while (**s == ' ' || **s == '\t' || **s == '\n' || **s == '\r') (*s)++;
        if (**s == '/' && *(*s + 1) == '/') {
            while (**s != '\0' && **s != '\n') (*s)++;
        } else {
            break;
        }
    }
}

void op_drop(VMContext *vm) { vm->sp--; }
void op_constant(VMContext *vm) { *vm->sp++ = FETCH(vm, double); }
void op_assign(VMContext *vm) { vm->expr->var_values[FETCH(vm, int)] = vm->sp[-1]; }
void op_variable(VMContext *vm) { *vm->sp++ = vm->expr->var_values[FETCH(vm, int)]; }
void op_neg(VMContext *vm) { vm->sp[-1] = - vm->sp[-1]; }
void op_add(VMContext *vm) { vm->sp[-2] += vm->sp[-1]; --vm->sp; }
void op_mul(VMContext *vm) { vm->sp[-2] *= vm->sp[-1]; --vm->sp; }
void op_sub(VMContext *vm) { vm->sp[-2] -= vm->sp[-1]; --vm->sp; }
void op_div(VMContext *vm) { vm->sp[-2] /= vm->sp[-1]; --vm->sp; }
void op_lt(VMContext *vm) { vm->sp[-2] = vm->sp[-2] < vm->sp[-1]; --vm->sp; }
void op_le(VMContext *vm) { vm->sp[-2] = vm->sp[-2] <= vm->sp[-1]; --vm->sp; }
void op_gt(VMContext *vm) { vm->sp[-2] = vm->sp[-2] > vm->sp[-1]; --vm->sp; }
void op_ge(VMContext *vm) { vm->sp[-2] = vm->sp[-2] >= vm->sp[-1]; --vm->sp; }
void op_eq(VMContext *vm) { vm->sp[-2] = vm->sp[-2] == vm->sp[-1]; --vm->sp; }
void op_ne(VMContext *vm) { vm->sp[-2] = vm->sp[-2] != vm->sp[-1]; --vm->sp; }
void op_bitand(VMContext *vm) { vm->sp[-2] = (unsigned)vm->sp[-2] & (unsigned)vm->sp[-1]; --vm->sp; }
void op_bitor(VMContext *vm) { vm->sp[-2] = (unsigned)vm->sp[-2] | (unsigned)vm->sp[-1]; --vm->sp; }
void op_bitxor(VMContext *vm) { vm->sp[-2] = (unsigned)vm->sp[-2] ^ (unsigned)vm->sp[-1]; --vm->sp; }
void op_lsh(VMContext *vm) { vm->sp[-2] = (unsigned)vm->sp[-2] << (unsigned)vm->sp[-1]; --vm->sp; }
void op_rsh(VMContext *vm) { vm->sp[-2] = (unsigned)vm->sp[-2] >> (unsigned)vm->sp[-1]; --vm->sp; }
void op_and(VMContext *vm) { vm->sp[-2] = vm->sp[-2]!=0 && vm->sp[-1]!=0; --vm->sp; }
void op_or(VMContext *vm) { vm->sp[-2] = vm->sp[-2]!=0 || vm->sp[-1]!=0; --vm->sp; }
void op_jmp(VMContext *vm) { int addr = FETCH(vm, int); vm->ip = vm->expr->code+addr; }
void op_jfalse(VMContext *vm) { int addr = FETCH(vm, int); if (vm->sp[-1] == 0) vm->ip = vm->expr->code+addr; }

typedef struct TOperator {
    const char *name;
    int level, rassoc;
    Opcode opcode;
} Operator;

static Operator ops[] = {
    { "*", 1, 0, op_mul }, { "/", 1, 0, op_div },
    { "+", 2, 0, op_add }, { "-", 2, 0, op_sub },
    { "&", 3, 0, op_bitand },
    { "|", 4, 0, op_bitor }, { "^", 4, 0, op_bitxor },
    { "<<", 5, 0, op_lsh }, { ">>", 5, 0, op_rsh },
    { "<", 6, 0, op_lt }, { "<=", 6, 0, op_le }, { ">", 6, 0, op_gt }, { ">=", 6, 0, op_ge },
       { "=", 6, 0, op_eq }, { "!=", 6, 0, op_ne },
    { "&&", 7, 0, op_and },
    { "||", 8, 0, op_or },
    { NULL },
};

#define MAX_LEVEL 9

static void parse(Expr *E, const char **s, int level, int sp) {
    if (level == 0) {
        skip_spaces(s);
        if (**s == '{') {
            ++(*s);
            int first = 1;
            for(;;) {
                skip_spaces(s);
                if (**s == '}') break;
                if (!first) emit(E, op_drop);
                first = 0;
                parse(E, s, MAX_LEVEL, sp);
                skip_spaces(s);
                if (**s == ';') ++(*s);
                else if (**s != '}') error("';' or '}' expected");
            }
            if (first) error("At least an expression is required in a block");
            ++(*s);
            return;
        } else if (**s == '(') {
            ++(*s);
            parse(E, s, MAX_LEVEL, sp);
            skip_spaces(s);
            if (**s != ')') error("')' expected");
            ++(*s);
            return;
        } else if (**s == '-') {
            ++(*s);
            parse(E, s, 0, sp);
            emit(E, op_neg);
            return;
        } else if ((**s >= '0' && **s <= '9') || **s == '.') {
            const char *s0 = *s;
            int ok = 0;
            while (**s >= '0' && **s <= '9') { ok=1; ++(*s); }
            if (**s == '.') {
                ++(*s);
                while (**s >= '0' && **s <= '9') { ok=1; ++(*s); }
            }
            if (!ok) error("Digits required either before or after decimal point");
            if (**s == 'e' || **s == 'E') {
                ++(*s);
                if (**s == '+' || **s == '-') ++(*s);
                if (!(**s >= '0' && **s <= '9')) error("Digits required for exponent");
                while (**s >= '0' && **s <= '9') ++(*s);
            }
            char *e = NULL;
            double v = strtod(s0, &e);
            if (e != *s) error("Invalid number");
            emit(E, op_constant);
            emit_bytes(E, &v, sizeof(v));
            if (sp+1 > E->stack_size) E->stack_size = sp+1;
            return;
        } else if ((**s >= 'a' && **s <= 'z') || (**s >= 'A' && **s <= 'Z') || **s == '_') {
            const char *s0 = *s;
            while ((**s >= 'a' && **s <= 'z') || (**s >= 'A' && **s <= 'Z') || **s == '_' ||
                   (**s >= '0' && **s <= '9')) {
               ++(*s);
            }
            int n = *s - s0, i = 0;
            if (n == 5 && strncmp(s0, "while", 5) == 0) {
                skip_spaces(s);
                if (**s != '(') error("'(' expected after 'while' keyword");
                int test_addr = E->code_size;
                parse(E, s, 0, sp);
                emit(E, op_jfalse);
                int jquit = E->code_size;
                emit_bytes(E, &jquit, sizeof(int));
                skip_spaces(s);
                if (**s != '{') error("'{' expected");
                emit(E, op_drop);
                parse(E, s, 0, sp);
                emit(E, op_drop);
                emit(E, op_jmp);
                emit_bytes(E, &test_addr, sizeof(test_addr));
                memcpy(E->code + jquit, &E->code_size, sizeof(E->code_size));
                return;
            }
            while (i<E->var_size && (strncmp(E->var_names[i], s0, n) != 0 || E->var_names[i][n] != '\0')) {
                ++i;
            }
            if (i == E->var_size) {
                if (E->var_size == E->var_alloc) {
                    int newalloc = E->var_alloc*2;
                    E->var_names = mem_realloc(E->var_names, newalloc*sizeof(const char *));
                    E->var_values = mem_realloc(E->var_values, newalloc*sizeof(double));
                    E->var_alloc = newalloc;
                }
                E->var_names[i] = mem_alloc(n+1);
                memcpy(E->var_names[i], s0, n);
                E->var_names[i][n] = '\0';
                E->var_values[i] = 0;
                E->var_size++;
            }
            skip_spaces(s);
            if (**s == ':' && *(*s+1) == '=') {
                *s += 2;
                parse(E, s, MAX_LEVEL, sp);
                emit(E, op_assign);
                emit_bytes(E, &i, sizeof(int));
            } else {
                emit(E, op_variable);
                emit_bytes(E, &i, sizeof(int));
                if (sp+1 > E->stack_size) E->stack_size = sp+1;
            }
            return;
        } else {
            fprintf(stderr, "---> '%s'\n", *s);
            error("Expression expected");
        }
    }
    parse(E, s, level-1, sp);
    for(;;) {
        skip_spaces(s);
        int op_index = -1, op_sz = -1;
        for (int i=0; ops[i].name; i++) {
            int sz = strlen(ops[i].name);
            if (strncmp(ops[i].name, *s, sz) == 0 && (op_index == -1 || op_sz < sz)) {
                op_index = i; op_sz = sz;
            }
        }
        if (op_index == -1 || ops[op_index].level != level) break;
        (*s) += op_sz;
        parse(E, s, (ops[op_index].rassoc ? level : level-1), sp+1);
        emit(E, ops[op_index].opcode);
    }
}

Expr *parse_expression(const char **s) {
    Expr *E = allocate_expression();
    parse(E, s, MAX_LEVEL, 0);
    return E;
}

double eval_expression(Expr *E) {
    VMContext vm = { E, alloca(E->stack_size * sizeof(double)), E->code };
    const unsigned char *end = E->code + E->code_size;
    while (vm.ip != end) {
        FETCH(&vm, Opcode)(&vm);
    }
    return vm.sp[-1];
}

int main(int argc, const char *argv[]) {
    for (int i=1; i<argc; i++) {
        printf("Expression text '%s'\n", argv[i]);
        const char *s = argv[i];
        Expr *e = parse_expression(&s);
        skip_spaces(&s);
        if (*s != '\0') error("Extra characters at end of expression");
        printf("Value --> %.18g\n", eval_expression(e));
        deallocate_expression(e);
    }
    return 0;
}