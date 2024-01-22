import re
from binaryninja import log
from binaryninja.plugin import PluginCommand, BackgroundTaskThread
from binaryninja.binaryview import BinaryReader
from binaryninja.types import Symbol, Type, NamedTypeReferenceBuilder
# Structure has been deprecated in favor of the StructureBuilder API.
try:
    from binaryninja.types import StructureBuilder
except ImportError:
    from binaryninja.types import Structure
from binaryninja.enums import SymbolType, ReferenceType

import sys
import os.path
# Prepend so if the itanium-demangler package is installed elsewhere it doesn't 
# interfere
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "itanium_demangler"))
from itanium_demangler import Node, parse as parse_mangled, is_ctor_or_dtor


def analyze_cxx_abi(view, start=None, length=None, task=None):
    platform = view.platform
    arch = platform.arch

    void_p_ty = Type.pointer(arch, Type.void())
    char_p_ty = Type.pointer(arch, Type.int(1))
    unsigned_int_ty = Type.int(arch.default_int_size, False)
    signed_int_ty = Type.int(arch.default_int_size, True)

    base_type_info_ty = Type.named_type(NamedTypeReferenceBuilder.create(
        name='std::type_info'))
    base_type_info_ptr_ty = Type.pointer(arch, base_type_info_ty)

    def char_array_ty(length):
        return Type.array(Type.int(1), strings[0].length)

    def type_info_ty(kind=None):
        try:
            type_info_struct = StructureBuilder.create()
        except NameError:
            type_info_struct = Structure()
        type_info_struct.append(void_p_ty, 'vtable')
        type_info_struct.append(char_p_ty, 'name')
        if kind == 'si_class':
            type_info_struct.append(base_type_info_ptr_ty, 'base_type')
        return Type.structure_type(type_info_struct)

    def vtable_ty(vfunc_count):
        try:
            vtable_struct = StructureBuilder.create()
        except NameError:
            vtable_struct = Structure()
        vtable_struct.append(signed_int_ty, 'top_offset')
        vtable_struct.append(base_type_info_ptr_ty, 'typeinfo')
        vtable_struct.append(Type.array(void_p_ty, vfunc_count), 'functions')
        return Type.structure_type(vtable_struct)

    if platform.name.startswith("windows-"):
        long_size = arch.default_int_size
    else:
        long_size = arch.address_size

    if arch.name.startswith('x86'):
        char_signed = True
    else:
        char_signed = False # not always true

    short_size = 2 # not always true
    long_long_size = 8 # not always true

    ty_for_cxx_builtin = {
        'void':                 Type.void(),
        'wchar_t':              Type.int(2, sign=char_signed, alternate_name='wchar_t'),
        'bool':                 Type.bool(),
        'char':                 Type.int(1, sign=char_signed),
        'signed char':          Type.int(1, sign=True),
        'unsigned char':        Type.int(1, sign=False),
        'short':                Type.int(short_size, sign=True),
        'unsigned short':       Type.int(short_size, sign=False),
        'int':                  Type.int(arch.default_int_size, sign=True),
        'unsigned int':         Type.int(arch.default_int_size, sign=False),
        'long':                 Type.int(long_size, sign=True),
        'unsigned long':        Type.int(long_size, sign=False),
        'long long':            Type.int(long_long_size, sign=True),
        'unsigned long long':   Type.int(long_long_size, sign=False),
        '__int128':             Type.int(16, sign=True),
        'unsigned __int128':    Type.int(16, sign=False),
        'float':                Type.float(4),
        'double':               Type.float(8),
        '__float80':            Type.float(10),
        '__float128':           Type.float(16),
        'char32_t':             Type.int(4, sign=char_signed, alternate_name='char32_t'),
        'char16_t':             Type.int(2, sign=char_signed, alternate_name='char16_t'),
    }

    def ty_from_demangler_node(node, cv_qual=frozenset(), arg_count_hint=None):
        if node.kind == 'builtin':
            if node.value in ty_for_cxx_builtin:
                return ty_for_cxx_builtin[node.value]
            else:
                return None
        elif node.kind in ['name', 'qual_name']:
            named_ty_ref = NamedTypeReferenceBuilder.create(name=str(node))
            return Type.named_type(named_ty_ref)
        elif node.kind in ['pointer', 'lvalue', 'rvalue']:
            pointee_ty = ty_from_demangler_node(node.value)
            if pointee_ty is None:
                return None
            is_const = ('const' in cv_qual)
            is_volatile = ('volatile' in cv_qual)
            if node.kind == 'pointer':
                return Type.pointer(arch, pointee_ty, is_const, is_volatile)
            elif node.kind == 'lvalue':
                return Type.pointer(arch, pointee_ty, is_const, is_volatile,
                                    ref_type=ReferenceType.ReferenceReferenceType)
            elif node.kind == 'rvalue':
                return Type.pointer(arch, pointee_ty, is_const, is_volatile,
                                    ref_type=ReferenceType.RValueReferenceType)
        elif node.kind == 'cv_qual':
            return ty_from_demangler_node(node.value, cv_qual=node.qual)
        elif node.kind == 'func':
            is_ctor_dtor = False
            if node.name and node.name.kind == 'qual_name':
                qual_name = node.name.value
                if qual_name[-1].kind in ['ctor', 'dtor']:
                    is_ctor_dtor = True

            if is_ctor_dtor:
                ret_ty = Type.void()
            elif node.ret_ty is not None:
                ret_ty = ty_from_demangler_node(node.ret_ty)
                if ret_ty is None:
                    return None
            else:
                ret_ty = Type.int(arch.default_int_size).with_confidence(0)

            arg_nodes = list(node.arg_tys)
            arg_tys = []

            var_arg = False
            if arg_nodes[-1].kind == 'builtin' and arg_nodes[-1].value == '...':
                arg_nodes.pop()
                var_arg = True
            elif arg_nodes[0].kind == 'builtin' and arg_nodes[0].value == 'void':
                arg_nodes = arg_nodes[1:]

            this_arg = False
            if node.name and node.name.kind == 'qual_name':
                qual_name = node.name.value
                if is_ctor_dtor or (arg_count_hint is not None and
                                    len(arg_nodes) == arg_count_hint - 1):
                    this_arg = True
                    this_node = Node('qual_name', qual_name[:-1])
                    this_ty = ty_from_demangler_node(this_node)
                    if this_ty is None:
                        return None
                    arg_tys.append(Type.pointer(arch, this_ty))
                    if is_ctor_dtor:
                        name = '::'.join(str(n) for n in qual_name[:-1])
                        if not name.startswith('std') and not view.get_type_by_name(name):
                            log.log_info(f'Registering new type {name}')
                            void_p_ty = Type.pointer(arch, Type.void())
                            with StructureBuilder.builder(view, name) as s:
                                s.append(Type.pointer(arch, void_p_ty), 'vtable')

            for arg_node in arg_nodes:
                arg_ty = ty_from_demangler_node(arg_node)
                if arg_ty is None:
                    return None
                arg_tys.append(arg_ty)

            ty = Type.function(ret_ty, arg_tys, variable_arguments=var_arg)
            if arg_count_hint is not None:
                # toplevel invocation, so return whether we inferred a this argument
                return this_arg, ty, is_ctor_dtor
            else:
                return ty
        else:
            log.log_warn("Cannot convert demangled AST {} to a type"
                         .format(repr(node)))

    reader = BinaryReader(view)
    def read(size):
        if size == 4:
            return reader.read32()
        elif size == 8:
            return reader.read64()
        else:
            assert False

    symbols = view.get_symbols(start, length)
    if task:
        task.set_total(len(symbols))

    mangled_re = re.compile('_?_Z')

    demangler_failures = 0
    for symbol in symbols:
        if task and not task.advance():
            break

        if not mangled_re.match(symbol.raw_name):
            continue

        is_data = (symbol.type == SymbolType.DataSymbol)
        is_code = (symbol.type in [SymbolType.FunctionSymbol,
                                   SymbolType.ImportedFunctionSymbol])

        raw_name, suffix = symbol.raw_name, ''
        if '@' in raw_name:
            match = re.match(r'^(.+?)(@.+)$', raw_name)
            raw_name, suffix = match.group(1), match.group(2)

        try:
            name_ast = parse_mangled(raw_name)
            if name_ast is None:
                log.log_warn("Demangler failed to recognize {}".format(raw_name))
                demangler_failures += 1
        except NotImplementedError as e:
            log.log_warn("Demangler feature missing on {}: {}".format(raw_name, str(e)))
            demangler_failures += 1

        if name_ast:
            if name_ast.kind == 'func':
                short_name = str(name_ast.name)
            else:
                short_name = str(name_ast)
            symbol = Symbol(symbol.type, symbol.address,
                short_name=short_name + suffix,
                full_name=str(name_ast) + suffix,
                raw_name=symbol.raw_name)
        else:
            symbol = Symbol(symbol.type, symbol.address,
                short_name=symbol.raw_name, full_name=None, raw_name=symbol.raw_name)
        view.define_auto_symbol(symbol)

        if name_ast is None:
            continue

        elif is_data and name_ast.kind == 'typeinfo_name':
            strings = view.get_strings(symbol.address, 1)
            if not strings:
                continue

            view.define_data_var(symbol.address, char_array_ty(length))

        elif is_data and name_ast.kind == 'typeinfo':
            reader.offset = symbol.address + arch.address_size * 2

            kind = None

            # heuristic: is this is an abi::__si_class_type_info?
            base_or_flags = read(arch.default_int_size)
            base_symbol = view.get_symbol_at(base_or_flags)
            if base_symbol and base_symbol.raw_name.startswith('_ZTI'):
                kind = 'si_class'

            view.define_data_var(symbol.address, type_info_ty(kind))

        elif is_data and name_ast.kind == 'vtable':
            vtable_addr = symbol.address

            reader.offset = vtable_addr + arch.address_size * 2
            while True:
                vfunc_count = 0
                check_next = True
                while True:
                    vfunc_ptr_symbol = view.get_symbol_at(reader.offset)
                    if vfunc_ptr_symbol and vfunc_ptr_symbol.raw_name.startswith('_Z'):
                        # any C++ symbol definitely terminates the vtable
                        check_next = False
                        break

                    # heuristic: existing function
                    vfunc_addr = read(arch.address_size)
                    if view.get_function_at(vfunc_addr):
                        vfunc_count += 1
                        continue

                    # explicitly reject null pointers; in position-independent code
                    # address zero can belong to the executable segment
                    if vfunc_addr == 0:
                        check_next = False
                        break

                    # heuristic: pointer to executable memory
                    vfunc_segment = view.get_segment_at(vfunc_addr)
                    if vfunc_addr != 0 and vfunc_segment and vfunc_segment.executable:
                        view.add_function(vfunc_addr)
                        vfunc_count += 1

                        log.log_info('Discovered function at {:#x} via {}'
                                     .format(vfunc_addr, symbol.full_name or symbol.short_name))
                        changed = True
                        continue

                    # we've fell off the end of the vtable
                    break

                view.define_data_var(vtable_addr, vtable_ty(vfunc_count))

                if check_next:
                    # heuristic: can another vtable follow this one? let's see if it has typeinfo,
                    # since that should be always true for when we have a virtual base
                    typeinfo_ptr = read(arch.address_size)
                    typeinfo_ptr_symbol = view.get_symbol_at(typeinfo_ptr)
                    if typeinfo_ptr_symbol and typeinfo_ptr_symbol.raw_name.startswith('_ZTI'):
                        vtable_addr = reader.offset - 2 * arch.address_size

                        # documentat it with a symbol
                        secondary_symbol_name = '{}_secondary_{:x}'.format(symbol.short_name,
                            vtable_addr - symbol.address)
                        secondary_symbol = Symbol(SymbolType.DataSymbol, vtable_addr,
                                                  short_name=secondary_symbol_name)
                        view.define_auto_symbol(secondary_symbol)
                        continue

                break

        elif is_code and name_ast.kind == 'func':
            func = view.get_function_at(symbol.address)

            ftype = getattr(func, 'type', None)
            if ftype is None:
                ftype = ftype.function_type
            
            demangled = ty_from_demangler_node(name_ast, arg_count_hint=len(ftype.parameters))
            if demangled is not None:
                this_arg, ty, dtor_ctor = demangled
                func.apply_auto_discovered_type(ty)
                if dtor_ctor and this_arg:
                    start = func.address_ranges[0].start
                    callers = list(view.get_callers(start))
                    for caller in callers:
                        try:
                            il_call = next(ins for ins in view.hlil_instructions if ins.address == caller.address)
                        except StopIteration:
                            continue

                        try:
                            # If the calling function is a ctor/dtor, it's 
                            # probably running inherited constructors
                            # so we shouldn't override the type
                            ast = parse_mangled(il_call.function.source_function.name)
                        except NotImplementedError as e:
                            log.log_warn("Demangler feature missing on {}: {}".format(il_call.function.source_function.name, str(e)))
                            demangler_failures += 1

                        if ast and is_ctor_or_dtor(ast):
                            continue
                        if not hasattr(il_call, 'params') or not il_call.params:
                            continue
                        this = il_call.params[0]
                        class_type = func.parameter_vars[0].type
                        if hasattr(this, 'var'):
                            this.var.type = class_type

    view.update_analysis()

    if demangler_failures:
        log.log_warn('{} demangler failures'.format(demangler_failures))


class CxxAbiAnalysis(BackgroundTaskThread):
    _PROGRESS_TEXT = 'Analyzing Itanium C++ ABI'

    def __init__(self, view):
        BackgroundTaskThread.__init__(self,
            initial_progress_text=self._PROGRESS_TEXT + "...", can_cancel=True)
        self._view = view
        self._total = 0
        self._current = 0

    def set_total(self, total):
        self._total = total

    def advance(self):
        self._current += 1
        self.progress = "{} ({}/{})...".format(self._PROGRESS_TEXT, self._current, self._total)
        return not self.cancelled

    def run(self):
        try:
            analyze_cxx_abi(self._view, task=self)
        finally:
            self.finish()


PluginCommand.register(
    'Analyze Itanium C++ ABI...',
    'Infer data types from C++ symbol names conforming to Itanium ABI.',
    lambda view: CxxAbiAnalysis(view).start()
)
