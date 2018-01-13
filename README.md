# Binary Ninja Itanium C++ ABI Plugin

The Itanium C++ ABI plugin provides a custom demangler, an analysis that decodes RTTI and vtables, and discovers new procedures based on virtual function pointers.

## Custom demangler

The custom demangler converts the mangled names into abstract syntax trees, allowing to extract more type information than the built-in one. For example, it differentiates between complete and base class constructors and destructors.

## RTTI and vtable decoding

Before / after:

<img src="doc/vtable-before.png" width="49%"> <img src="doc/vtable-after.png" width="49%">

## License

[0-clause BSD](LICENSE-0BSD.txt)
