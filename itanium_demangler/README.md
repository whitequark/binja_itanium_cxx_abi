# Itanium Demangler

The *Python Itanium Demangler* is a pure Python parser for the [Itanium C++ ABI symbol mangling language][manglang]. Note that MSVC mangling language is not supported.

This demangler generates an abstract syntax tree from mangled symbols, which can be used for directly extracting type information, as opposed to having to interpret the C++ source code corresponding to the demangled symbol

 There is also a built-in AST stringifier, so the demangler can be used as a replacement for `c++filt` or for formatting backtraces.

[manglang]: https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling

## Requirements

The demangler runs on Python 2.7 and 3.3+ and has no dependencies.

## Installation

Installing via PyPI:

    pip install itanium_demangler

Using a local repository for development:

    git clone https://github.com/whitequark/python-itanium_demangler
    cd python-itanium_demangler
    python setup.py develop --user

## Usage

```python
from itanium_demangler import parse as demangle

ast = demangle("_ZN5boost6chrono24process_system_cpu_clock3nowEv")

print(repr(ast))
# <FuncNode func <Node qual_name (<Node name 'boost'>, <Node name 'chrono'>, <Node name 'process_system_cpu_clock'>, <Node name 'now'>)> (<Node builtin 'void'>,) None>

print(ast)
# boost::chrono::process_system_cpu_clock::now()
```

## Future considerations

A similar (i.e. also parsing to an AST) implementation of a demangler for the MSVC mangling language would be useful to have.

## License

[0-clause BSD](LICENSE-0BSD.txt)
