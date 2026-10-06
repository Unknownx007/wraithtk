__author__ = "DEDSEC"
__tool__ = "WraithTK"
__version__ = "0.1.0"
__license__ = "AGPL-3.0-or-later"


def verify_provenance() -> None:
    import sys
    if __author__ != "DEDSEC" or __tool__ != "WraithTK":
        sys.stderr.write("\n[!] Provenance check failed: original author credit missing.\n")
        sys.exit(3)
