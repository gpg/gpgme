Python CFFI Proof of Concept
============================


This is a proof-of-concept initial test for (eventually) switching fro the Python and SWIG bindings to a Python and CFFI method.

This is intended to address multiple issues, including:

* Interoperability between platforms
* Easier maintenance
* Greater interoperability with third party security modules (e.g. pyca/cryptography)

It may also provide the following (no guarantees, though):

* Use on Windows without massive errors (and complaints).
* Use on PyPy as well as CPython and thus may eventually be integrated with other Python implementations (e.g. QPython on Android).
* It might allow use of Python 3.2 and/or 3.3, but they're not super urgent since we're up to 3.6 now and the changes/improvements made by 3.4 are very useful anyway.

The down sides are:

* It requires a full re-implementation from scratch (during which the SWIG based version would need to remain active).
* Windows will probably still require a special implementation just for itself (probably ABI out-of-line, while all other platformsuse API out-of-line; otherwise it also requires end users running various C compilers, this way we just need to build GPGME DLLs for Windows).
* Will require dropping support for Python 2.6.
* Might require dropping support for Python 2.7.
* It may not generate bindings in the same way that SWIG does, but that's offset by making it castly simpler to do that manually and that part may become scriptable later anyway.

