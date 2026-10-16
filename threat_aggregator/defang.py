"""
Defanging and Refanging Utilities
Practical cybersecurity techniques for safely parsing and presenting indicators of compromise.
"""

import re

# Common defanging replacements
REFANG_PATTERNS = [
    # Protocols
    (re.compile(r"^hxxps?://", re.IGNORECASE), lambda m: "https://" if m.group(0).lower().startswith("hxxps") else "http://"),
    (re.compile(r"^hXXps?://", re.IGNORECASE), lambda m: "https://" if m.group(0).lower().startswith("hxxps") else "http://"),
    (re.compile(r"^fxps?://", re.IGNORECASE), lambda m: "ftp://"),
    (re.compile(r"^me:\/\/", re.IGNORECASE), lambda m: ""),

    # Bracketed dots
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\{\.\}"), "."),
    (re.compile(r"\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\(dot\)", re.IGNORECASE), "."),

    # Bracketed colons
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\(\:\)"), ":"),

    # Bracketed at-sign for emails
    (re.compile(r"\[@\]"), "@"),
    (re.compile(r"\(@\)"), "@"),
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\(at\)", re.IGNORECASE), "@"),
]


def refang(value: str) -> str:
    """
    Restores defanged indicators to their canonical, functional format.
    E.g. 'hxxp://evil[.]com/bad[.]exe' -> 'http://evil.com/bad.exe'
         '192[.]168[.]1[.]1' -> '192.168.1.1'
    """
    if not value:
        return ""
    
    clean_val = value.strip().strip("'\"`<>")
    for pattern, repl in REFANG_PATTERNS:
        if callable(repl):
            clean_val = pattern.sub(repl, clean_val)
        else:
            clean_val = pattern.sub(repl, clean_val)
    return clean_val.strip()


def defang(value: str) -> str:
    """
    Defangs an active indicator so it cannot be accidentally executed,
    queried, or clicked by humans or automated systems.
    E.g. 'http://evil.com' -> 'hxxp://evil[.]com'
         '1.2.3.4' -> '1[.]2[.]3[.]4'
    """
    if not value:
        return ""

    val = value.strip()
    # Protocols
    val = re.sub(r"^https://", "hxxps://", val, flags=re.IGNORECASE)
    val = re.sub(r"^http://", "hxxp://", val, flags=re.IGNORECASE)
    val = re.sub(r"^ftp://", "fxp://", val, flags=re.IGNORECASE)

    # Dots
    val = val.replace(".", "[.]")

    # At signs
    val = val.replace("@", "[@]")

    return val
