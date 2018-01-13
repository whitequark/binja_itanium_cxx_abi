import re
from collections import namedtuple


class _Cursor:
    def __init__(self, raw, pos=0):
        self._raw = raw
        self._pos = pos

    def at_end(self):
        return self._pos == len(self._raw)

    def peek(self):
        return self._raw[self._pos]

    def advance(self, amount):
        if self._pos + amount > len(self._raw):
            return None
        result = self._raw[self._pos:self._pos + amount]
        self._pos += amount
        return result

    def match(self, pattern):
        match = pattern.match(self._raw, self._pos)
        if match:
            self._pos = match.end(0)
        return match


class Node(namedtuple('Node', 'kind value')):
    # Kinds: name ctor dtor operator qual_name vtable vtt typeinfo typeinfo_name
    def __str__(self):
        if self.kind == 'name':
            return self.value
        elif self.kind == 'ctor':
            if self.value == 1:
                return '{complete ctor}'
            elif self.value == 2:
                return '{base ctor}'
            elif self.value == 3:
                return '{allocating ctor}'
        elif self.kind == 'dtor':
            if self.value == 0:
                return '{deleting dtor}'
            elif self.value == 1:
                return '{complete dtor}'
            elif self.value == 2:
                return '{base dtor}'
        elif self.kind == 'operator':
            if self.value.startswith('new') or self.value.startswith('delete'):
                return 'operator ' + self.value
            else:
                return 'operator' + self.value
        elif self.kind == 'qual_name':
            return '::'.join(map(str, self.value))
        elif self.kind == 'vtable':
            return 'vtable for ' + str(self.value)
        elif self.kind == 'vtt':
            return 'vtt for ' + str(self.value)
        elif self.kind == 'typeinfo':
            return 'typeinfo for ' + str(self.value)
        elif self.kind == 'typeinfo_name':
            return 'typeinfo name for ' + str(self.value)
        else:
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

_NAME_RE = re.compile(r"""
(?P<source_name>   \d+)    |
(?P<ctor_name>     C (?P<ctor_kind> [123])) |
(?P<dtor_name>     D (?P<dtor_kind> [012])) |
(?P<std_name>      S[absiod]) |
(?P<operator_name> nw|na|dl|da|ps|ng|ad|de|co|pl|mi|ml|dv|rm|an|or|
                   eo|aS|pL|mI|mL|dV|rM|aN|oR|eO|ls|rs|lS|rS|eq|ne|
                   lt|gt|le|ge|nt|aa|oo|pp|mm|cm|pm|pt|cl|ix|qu) |
(?P<std_prefix>    St) |
(?P<nested_name>   N (?P<cv_qual> r?V?K?) (?P<ref_qual> [RO]?))
""", re.X)

def parse_name(cursor):
    match = cursor.match(_NAME_RE)
    if match is None:
        return None
    elif match.group('source_name'):
        name_len = int(match.group('source_name'))
        name = cursor.advance(name_len)
        if name is None:
            return None
        return Node('name', name)
    elif match.group('ctor_name'):
        return Node('ctor', int(match.group('ctor_kind')))
    elif match.group('dtor_name'):
        return Node('dtor', int(match.group('dtor_kind')))
    elif match.group('std_name'):
        return Node('name', _std_names[match.group('std_name')])
    elif match.group('operator_name'):
        return Node('operator', _operators[match.group('operator_name')])
    elif match.group('std_prefix'):
        node = parse_name(cursor)
        if node is None:
            return None
        return Node('qual_name', [Node('name', 'std'), node])
    elif match.group('nested_name'):
        nodes = []
        while cursor.peek() != 'E':
            node = parse_name(cursor)
            if node is None or cursor.at_end():
                return None
            nodes.append(node)
        return Node('qual_name', nodes)


_SPECIAL_RE = re.compile(r"""
(?P<special>       T (?P<kind> [VTIS]))
""", re.X)

def parse_special(cursor):
    match = cursor.match(_SPECIAL_RE)
    if match is None:
        return None
    elif match.group('special'):
        name = parse_name(cursor)
        if name is None:
            return None
        if match.group('kind') == 'V':
            return Node('vtable', name)
        elif match.group('kind') == 'T':
            return Node('vtt', name)
        elif match.group('kind') == 'I':
            return Node('typeinfo', name)
        elif match.group('kind') == 'S':
            return Node('typeinfo_name', name)


def parse(raw):
    cursor = _Cursor(raw)
    if cursor.advance(2) == '_Z':
        special = parse_special(cursor)
        if special is not None:
            return special
        return parse_name(cursor)


if __name__ == '__main__':
    import sys
    ast = parse(sys.argv[1])
    print(ast)
