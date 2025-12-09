# yara_test.py
import yara
import sys

rule_source = r'''
rule ContainsHTTP {
    strings:
        $s = "http"
    condition:
        $s
}
'''

if len(sys.argv) < 2:
    print("Usage: python yara_test.py <path-to-file>")
    sys.exit(1)

rules = yara.compile(source=rule_source)
matches = rules.match(sys.argv[1])
print("Matches:", matches)
