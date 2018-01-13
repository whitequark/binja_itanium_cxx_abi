# encoding:utf-8

import re
from collections import namedtuple


class _Cursor:
    def __init__(self, raw, pos=0):
        self._raw = raw
        self._pos = pos

    def at_end(self):
        return self._pos == len(self._raw)

    def accept(self, delim):
        if self._raw[self._pos:self._pos + len(delim)] == delim:
            self._pos += len(delim)
            return True

    def advance(self, amount):
        if self._pos + amount > len(self._raw):
            return None
        result = self._raw[self._pos:self._pos + amount]
        self._pos += amount
        return result

    def advance_until(self, delim):
        new_pos = self._raw.find(delim, self._pos)
        if new_pos == -1:
            return None
        result = self._raw[self._pos:new_pos]
        self._pos = new_pos + len(delim)
        return result

    def match(self, pattern):
        match = pattern.match(self._raw, self._pos)
        if match:
            self._pos = match.end(0)
        return match

    def __repr__(self):
        return "_Cursor({}, {})".format(self._raw[:self._pos] + '→' + self._raw[self._pos:],
                                        self._pos)


class Node(namedtuple('Node', 'kind value')):
    # Kinds: (name) name nested_name template_args ctor dtor operator
    #        (type) cv_qual pointer lvalue rvalue function literal
    #        (special) vtable vtt typeinfo typeinfo_name
    def __str__(self):
        if self.kind == 'name':
            return self.value
        elif self.kind == 'nested_name':
            result = ''
            for node in self.value:
                if result != '' and node.kind != 'template_args':
                    result += '::'
                result += str(node)
            return result
        elif self.kind == 'template_args':
            return '<' + ', '.join(map(str, self.value)) + '>'
        elif self.kind == 'ctor':
            if self.value == 1:
                return '{ctor}'
            elif self.value == 2:
                return '{base ctor}'
            elif self.value == 3:
                return '{allocating ctor}'
        elif self.kind == 'dtor':
            if self.value == 0:
                return '{deleting dtor}'
            elif self.value == 1:
                return '{dtor}'
            elif self.value == 2:
                return '{base dtor}'
        elif self.kind == 'operator':
            if self.value.startswith('new') or self.value.startswith('delete'):
                return 'operator ' + self.value
            else:
                return 'operator' + self.value
        elif self.kind == 'cv_qual':
            qualifiers, ty = self.value
            str_qualifiers = ' '.join(list(qualifiers))
            if ty.kind in ('pointer', 'lvalue', 'rvalue'):
                return str(ty) + ' ' + str_qualifiers
            else:
                return str_qualifiers + ' ' + str(ty)
        elif self.kind == 'pointer':
            return str(self.value) + '*'
        elif self.kind == 'lvalue':
            return str(self.value) + '&'
        elif self.kind == 'rvalue':
            return str(self.value) + '&&'
        elif self.kind == 'function':
            name, args = self.value
            if args == (Node('name', 'void'),):
                return str(name) + '()'
            else:
                return str(name) + '(' + ', '.join(map(str, args)) + ')'
        elif self.kind == 'literal':
            ty, value = self.value
            return '(' + str(ty) + ')' + str(value)
        elif self.kind == 'vtable':
            return 'vtable for ' + str(self.value)
        elif self.kind == 'vtt':
            return 'vtt for ' + str(self.value)
        elif self.kind == 'typeinfo':
            return 'typeinfo for ' + str(self.value)
        elif self.kind == 'typeinfo_name':
            return 'typeinfo name for ' + str(self.value)
        else:
            print(self.kind)
            assert False


_std_names = {
    'St': [Node('name', 'std')],
    'Sa': [Node('name', 'std'), Node('name', 'allocator')],
    'Sb': [Node('name', 'std'), Node('name', 'basic_string')],
    'Ss': [Node('name', 'std'), Node('name', 'string')],
    'Si': [Node('name', 'std'), Node('name', 'istream')],
    'So': [Node('name', 'std'), Node('name', 'ostream')],
    'Sd': [Node('name', 'std'), Node('name', 'iostream')],
}

_operators = {
    'nw': 'new',
    'na': 'new[]',
    'dl': 'delete',
    'da': 'delete[]',
    'ps': '+', # (unary)
    'ng': '-', # (unary)
    'ad': '&', # (unary)
    'de': '*', # (unary)
    'co': '~',
    'pl': '+',
    'mi': '-',
    'ml': '*',
    'dv': '/',
    'rm': '%',
    'an': '&',
    'or': '|',
    'eo': '^',
    'aS': '=',
    'pL': '+=',
    'mI': '-=',
    'mL': '*=',
    'dV': '/=',
    'rM': '%=',
    'aN': '&=',
    'oR': '|=',
    'eO': '^=',
    'ls': '<<',
    'rs': '>>',
    'lS': '<<=',
    'rS': '>>=',
    'eq': '==',
    'ne': '!=',
    'lt': '<',
    'gt': '>',
    'le': '<=',
    'ge': '>=',
    'nt': '!',
    'aa': '&&',
    'oo': '||',
    'pp': '++', # (postfix in <expression> context)
    'mm': '--', # (postfix in <expression> context)
    'cm': ',',
    'pm': '->*',
    'pt': '->',
    'cl': '()',
    'ix': '[]',
    'qu': '?',
}

_builtin_types = {
    'v':  'void',
    'w':  'wchar_t',
    'b':  'bool',
    'c':  'char',
    'a':  'signed char',
    'h':  'unsigned char',
    's':  'short',
    't':  'unsigned short',
    'i':  'int',
    'j':  'unsigned int',
    'l':  'long',
    'm':  'unsigned long',
    'x':  'long long',
    'y':  'unsigned long long',
    'n':  '__int128',
    'o':  'unsigned __int128',
    'f':  'float',
    'd':  'double',
    'e':  '__float80',
    'g':  '__float128',
    'z':  '...',
    'Di': 'char32_t',
    'Ds': 'char16_t',
    'Da': 'auto',
}


def _parse_until_end(cursor, kind, fn):
    nodes = []
    while not cursor.accept('E'):
        node = fn(cursor)
        if node is None or cursor.at_end():
            return None
        nodes.append(node)
    return Node(kind, nodes)

def _parse_source_name(cursor, length):
    name_len = int(length)
    name = cursor.advance(name_len)
    if name is None:
        return None
    return Node('name', name)


_NAME_RE = re.compile(r"""
(?P<source_name>        \d+)    |
(?P<ctor_name>          C (?P<ctor_kind> [123])) |
(?P<dtor_name>          D (?P<dtor_kind> [012])) |
(?P<std_name>           S[absiod]) |
(?P<operator_name>      nw|na|dl|da|ps|ng|ad|de|co|pl|mi|ml|dv|rm|an|or|
                        eo|aS|pL|mI|mL|dV|rM|aN|oR|eO|ls|rs|lS|rS|eq|ne|
                        lt|gt|le|ge|nt|aa|oo|pp|mm|cm|pm|pt|cl|ix|qu) |
(?P<std_prefix>         St) |
(?P<nested_name>        N (?P<cv_qual> [rVK]*) (?P<ref_qual> [RO]?)) |
(?P<template_args>      I)
""", re.X)

def _parse_name(cursor):
    match = cursor.match(_NAME_RE)
    if match is None:
        return None
    elif match.group('source_name') is not None:
        node = _parse_source_name(cursor, match.group('source_name'))
        if node is None:
            return None
    elif match.group('ctor_name') is not None:
        node = Node('ctor', int(match.group('ctor_kind')))
    elif match.group('dtor_name') is not None:
        node = Node('dtor', int(match.group('dtor_kind')))
    elif match.group('std_name') is not None:
        node = Node('nested_name', _std_names[match.group('std_name')])
    elif match.group('operator_name') is not None:
        node = Node('operator', _operators[match.group('operator_name')])
    elif match.group('std_prefix') is not None:
        name = _parse_name(cursor)
        if name is None:
            return None
        node = Node('nested_name', [Node('name', 'std'), name])
    elif match.group('nested_name') is not None:
        node = _parse_until_end(cursor, 'nested_name', _parse_name)
    elif match.group('template_args') is not None:
        node = _parse_until_end(cursor, 'template_args', _parse_type)
    if node is None:
        return None

    if cursor.accept('I'):
        templ_args = _parse_until_end(cursor, 'template_args', _parse_type)
        if templ_args is None:
            return None
        node = Node('nested_name', [node, templ_args])

    return node


_TYPE_RE = re.compile(r"""
(?P<builtin_type>       v|w|b|c|a|h|s|t|i|j|l|m|x|y|n|o|f|d|e|g|z|
                        Dd|De|Df|Dh|DF|Di|Ds|Da|Dc|Dn) |
(?P<qualified_type>     [rVK]+) |
(?P<indirect_type>      [PRO]) |
(?P<expr_primary>       (?= L))
""", re.X)

def _parse_type(cursor):
    match = cursor.match(_TYPE_RE)
    if match is None:
        return _parse_name(cursor)
    elif match.group('builtin_type') is not None:
        return Node('name', _builtin_types[match.group('builtin_type')])
    elif match.group('qualified_type') is not None:
        qualifiers = set()
        if 'r' in match.group('qualified_type'):
            qualifiers.add('restrict')
        if 'V' in match.group('qualified_type'):
            qualifiers.add('volatile')
        if 'K' in match.group('qualified_type'):
            qualifiers.add('const')
        ty = _parse_type(cursor)
        if ty is None:
            return None
        return Node('cv_qual', (qualifiers, ty))
    elif match.group('indirect_type') is not None:
        ty = _parse_type(cursor)
        if ty is None:
            return None
        if match.group('indirect_type') == 'P':
            return Node('pointer', ty)
        elif match.group('indirect_type') == 'R' is not None:
            return Node('lvalue', ty)
        elif match.group('indirect_type') == 'O' is not None:
            return Node('rvalue', ty)
    elif match.group('expr_primary') is not None:
        return _parse_expr_primary(cursor)


_EXPR_PRIMARY_RE = re.compile(r"""
(?P<mangled_name>       L (?= _Z)) |
(?P<literal>            L)
""", re.X)

def _parse_expr_primary(cursor):
    match = cursor.match(_EXPR_PRIMARY_RE)
    if match is None:
        return None
    elif match.group('mangled_name') is not None:
        return _parse_mangled_name(cursor)
    elif match.group('literal') is not None:
        ty = _parse_type(cursor)
        if ty is None:
            return None
        value = cursor.advance_until('E')
        if value is None:
            return None
        return Node('literal', (ty, value))


_SPECIAL_RE = re.compile(r"""
(?P<special>            T (?P<kind> [VTIS]))
""", re.X)

def _parse_special(cursor):
    match = cursor.match(_SPECIAL_RE)
    if match is None:
        return None
    elif match.group('special') is not None:
        name = _parse_name(cursor)
        if name is None:
            return None
        if match.group('kind') == 'V':
            return Node('vtable', name)
        elif match.group('kind') == 'T' is not None:
            return Node('vtt', name)
        elif match.group('kind') == 'I' is not None:
            return Node('typeinfo', name)
        elif match.group('kind') == 'S' is not None:
            return Node('typeinfo_name', name)


_MANGLED_NAME_RE = re.compile(r"""
(?P<mangled_name>       _Z)
""", re.X)

def _parse_mangled_name(cursor):
    match = cursor.match(_MANGLED_NAME_RE)
    if match is None:
        return None
    else:
        special = _parse_special(cursor)
        if special is not None:
            return special

        name = _parse_name(cursor)
        if name is None:
            return None

        arg_types = []
        while not cursor.at_end():
            arg_type = _parse_type(cursor)
            if arg_type is None:
                return None
            arg_types.append(arg_type)

        if arg_types:
            return Node('function', (name, tuple(arg_types)))
        else:
            return name


def parse(raw):
    return _parse_mangled_name(_Cursor(raw))


if __name__ == '__main__':
    import sys
    ast = parse(sys.argv[1])
    print(repr(ast))
    print(ast)
