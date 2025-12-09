# pe_info.py
import pefile
import sys

if len(sys.argv) < 2:
    print("Usage: python pe_info.py <path-to-pe>")
    sys.exit(1)

path = sys.argv[1]
pe = pefile.PE(path)

print("Entry Point:", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print("Image Base:", hex(pe.OPTIONAL_HEADER.ImageBase))
print("Number of sections:", len(pe.sections))

if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    print("\nImported DLLs and (first few) functions:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(" ", entry.dll.decode(errors='ignore'))
        for imp in entry.imports[:10]:
            name = imp.name.decode(errors='ignore') if imp.name else "<ordinal>"
            print("     -", name)
else:
    print("No import table found or packed.")
