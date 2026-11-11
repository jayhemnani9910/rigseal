"""Rules over the text of skills, commands, agents, rules and plugins (R7-R14).

Patterns come from real campaigns: ClawHavoc (fake prerequisites, base64 -> curl -> stealer, password zips,
reverse shells) and SkillCloak (homoglyphs, split commands, payloads hidden in dotfolders).
Text is folded first (NFKC + common look-alike letters), so `curl` written with a Cyrillic c still matches.
"""

from __future__ import annotations

import re
import unicodedata
from bisect import bisect_left
from pathlib import PurePosixPath

from rigseal.lock import item_key
from rigseal.model import Finding, Item

TEXT_RULE_KINDS = {"skill", "command", "agent", "rule", "instructions", "prompt", "plugin"}

# Cyrillic and Greek letters that look like Latin ones.
HOMOGLYPHS = str.maketrans(
    "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u0501\u0261\u04bb\u04cf\u051b\u051d\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u0406\u0408\u0405\u051c\u03b1\u03bf\u03bf\u03c1\u03c4\u03c5\u03bd\u03ba\u03b9\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7",
    "aeopcyxijsdghlqwABEKMHOPCTXIJSWaoopTuvkiABEZHIKMNOPTYX",
)
CYRILLIC = re.compile(r"[\u0400-\u04ff]")  # Greek is left out: math text mixes it with Latin (d-psi-dx)
LATIN = re.compile(r"[A-Za-z]")
LETTER_RUN = re.compile(r"(?:[^\W\d_]|[\u0400-\u04ff])+")  # letters, plus the Cyrillic marks that aren't letters


def fold(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(HOMOGLYPHS)


def mixed_word(text: str) -> bool:
    """A run of letters that holds both a Latin and a Cyrillic one. Each run is read once, however long it is."""
    return any(LATIN.search(w) and CYRILLIC.search(w) for w in LETTER_RUN.findall(text) if not w.isascii())


def followed_by(first: str, then: str, between: str = r"[^\n]") -> str:
    """Regex for `first` with `then` further along. The text between can't hold another `first`: the search starts
    again there instead of reading the rest of the line once more, so a long line of repeats stays cheap."""
    return rf"(?:{first})(?:(?!{first}){between})*(?:{then})"


# Binaries, archives, release assets, paste sites, shorteners, tunnels, raw IPs. Not install scripts: docs use those a lot.
DOWNLOAD_URL = re.compile(
    followed_by(r"https?://", r"\.(zip|exe|dmg|pkg|msi|7z|rar|appimage|scr)\b|/releases/download/", r"[^\s)\]>'\"]") + "|"
    r"https?://(www\.)?(glot\.io|pastebin\.com|paste\.ee|hastebin\.com|transfer\.sh|bit\.ly|tinyurl\.com|[\w-]+\.ngrok\S*|[\w-]+\.trycloudflare\.com)|"
    r"https?://\d{1,3}(\.\d{1,3}){3}",
    re.I,
)
PREREQ = re.compile(
    r"\b(prerequisite|pre-requisite|required (dependency|component|tool|agent|helper)|"
    r"(must|need to|should) (first )?(download|install|run)|before (using|you (use|start|begin)|running) (this|the)|"
    r"(install|download|run) (this|the following|it) (first|before))",
    re.I,
)
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
HEX_BLOB = re.compile(r"(\\x[0-9a-fA-F]{2}){20,}|\b[0-9a-fA-F]{100,}\b")
DECODE = re.compile(
    r"base64\s+(-d|--decode|-D)\b|b64decode|atob\s*\(|from\(\s*(?:(?!from\()\S)+\s*,\s*['\"]base64|FromBase64String|certutil\s+-decode|"
    r"bytes\.fromhex|unhexlify|xxd\s+-r|codecs\.decode",
    re.I,
)
EXEC_DECODED = re.compile(
    followed_by(r"base64\s+(-d|--decode|-D)|xxd\s+-r|openssl\s+(enc|base64)\s+-d", r"\|\s*(sudo\s+)?(ba|z|da)?sh\b", r"[^\n|]") + "|"
    r"\b(eval|exec)\s*\(\s*(atob|Buffer\.from|base64|b64decode|codecs|bytes\.fromhex|zlib|marshal|compile)|"
    r"\bexec\s*\(\s*open\s*\(|\beval\s*\(\s*(fs\.)?readFileSync|"
    r"iex\s*\(\s*(New-Object\s+Net\.WebClient|irm|iwr|Invoke-RestMethod|Invoke-WebRequest)|\|\s*iex\b",
    re.I,
)
# Common in honest install docs, so medium: `curl https://x/install.sh | bash`.
PIPE_TO_SHELL = re.compile(
    followed_by(r"\b(curl|wget)\b", r"\|\s*((sudo\s+)?(ba|z|da)?sh|python3?|perl|ruby|node)\b", r"[^\n|]") + "|"
    r"(eval|source)\s+\"?\$\(\s*(curl|wget)|source\s+<\(\s*(curl|wget)",
    re.I,
)
ARCHIVE = re.compile(r"\.(zip|rar|7z)\b|\b(zip|archive|rar|7z|7-zip)\b", re.I)
ARCHIVE_PASSWORD = re.compile(r"\b(password|passcode)\b\s*(is|[:=])\s*[`'\"*]*\S{3,}", re.I)
REVERSE_SHELL = re.compile(
    r"/dev/(tcp|udp)/|" + followed_by(r"\bn(c|cat|etcat)\b", r"\s-(e|c)\s") + r"|bash\s+-i\s*>&|\bsh\s+-i\s*[<>]&|"
    + followed_by("mkfifo", r"\bn(c|cat)\b") + "|" + followed_by(r"socat\b", "exec:")
    + r"|pty\.spawn\s*\(|os\.dup2\s*\(\s*\w+\.fileno\(\)",
    re.I,
)
PY_SOCKET_SHELL = (re.compile(r"socket\.socket\s*\("), re.compile(r"os\.dup2|pty\.spawn|stdin\s*=\s*\w+\.(fileno|makefile)"))
STRONG_SECRETS = re.compile(
    r"~/\.ssh|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.git-credentials|\.gnupg|/etc/shadow|"
    r"Keychains?/|wallet\.dat|\.bitcoin|electrum|exodus|metamask|Login Data|Cookies\.binarycookies|\.config/(google-chrome|chromium|BraveSoftware)",
    re.I,
)
NETWORK_CALL = re.compile(r"\b(curl|wget|Invoke-WebRequest|requests\.(get|post|put)|urllib\.request|httpx\.|fetch\(|axios\.|nc\s)")
FENCE = re.compile(r"```[^`\n]*\n(.*?)```", re.S)
CODE_SUFFIXES = {".sh", ".bash", ".zsh", ".ps1", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl"}

BINARY_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".scr", ".com", ".msi", ".app", ".jar", ".pyc", ".node"}
ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".dmg", ".pkg", ".deb", ".rpm"}
OK_DOTDIRS = {".github", ".claude-plugin", ".codex-plugin", ".cursor-plugin", ".vscode"}


# Substrings a match can't do without. The regexes are slow on big files, so they only run when a hint is there.
HINTS: dict[re.Pattern, tuple[str, ...]] = {
    PREREQ: ("prereq", "pre-req", "required", "must", "need to", "should", "before", "first"),
    DOWNLOAD_URL: ("http",),
    DECODE: ("base64", "b64decode", "atob", "fromhex", "unhexlify", "xxd", "certutil", "codecs"),
    ARCHIVE_PASSWORD: ("password", "passcode"),
    REVERSE_SHELL: ("/dev/tcp", "/dev/udp", "nc", "cat", "bash -i", "sh -i", "mkfifo", "socat", "pty.spawn", "dup2"),
    STRONG_SECRETS: (
        ".ssh", "id_rsa", "id_ed25519", ".aws", ".git-credentials", ".gnupg", "/etc/shadow", "keychain", "wallet",
        "bitcoin", "electrum", "exodus", "metamask", "login data", "cookies", "google-chrome", "chromium", "bravesoftware",
    ),
    EXEC_DECODED: ("base64", "xxd", "openssl", "eval", "exec", "iex"),
    PIPE_TO_SHELL: ("curl", "wget", "source"),
}  # fmt: skip


def _search(pattern: re.Pattern, text: str, lower: str) -> re.Match | None:
    hints = HINTS.get(pattern)
    if hints and not any(h in lower for h in hints):
        return None
    return pattern.search(text)


def file_hits(text: str, suffix: str) -> tuple[tuple[str, str, str], ...]:
    """(rule, severity, message) for one file's text, without the file name."""
    f = fold(text)
    low = f.lower()
    hits: list[tuple[str, str, str]] = []

    # R7: "install this first" next to a direct download link.
    if (p := _search(PREREQ, f, low)) and "http" in low:
        if any(abs(m.start() - p.start()) < 600 for m in DOWNLOAD_URL.finditer(f)):
            hits.append(("R7", "high", "asks you to install a prerequisite from a direct download link"))

    # R8: something that decodes, plus an encoded blob for it to decode.
    if _search(DECODE, f, low) and (B64_BLOB.search(f) or HEX_BLOB.search(f)):
        hits.append(("R8", "high", "encoded blob with a decoder"))

    # R9: password-protected archive, password given next to it.
    if _search(ARCHIVE_PASSWORD, f, low):
        archives = [a.start() for a in ARCHIVE.finditer(f)]  # in order, so the nearest one is a binary search away
        for m in ARCHIVE_PASSWORD.finditer(f):
            i = bisect_left(archives, m.start() - 299)
            if i < len(archives) and archives[i] < m.start() + 300:
                hits.append(("R9", "medium", "password-protected archive with the password in the text"))
                break

    # R10: reverse shell.
    if _search(REVERSE_SHELL, f, low) or ("socket" in low and all(p.search(f) for p in PY_SOCKET_SHELL)):
        hits.append(("R10", "high", "reverse shell pattern"))

    # R11: code that touches keys, wallets or browser data and also makes a network call.
    if any(h in low for h in HINTS[STRONG_SECRETS]):
        code = f if suffix in CODE_SUFFIXES else "\n".join(FENCE.findall(f))
        if (m := STRONG_SECRETS.search(code)) and NETWORK_CALL.search(code):
            hits.append(("R11", "high", f"code touches secrets ({m.group(0)}) and makes a network call"))

    # R13: words that mix Latin and Cyrillic letters. Checked before folding, which would hide them.
    if CYRILLIC.search(text) and mixed_word(unicodedata.normalize("NFKC", text)):
        hits.append(("R13", "high", "words mixing Latin and Cyrillic letters"))

    # R14: decode, then run. Piping a download into a shell is common in honest docs, so only medium.
    if _search(EXEC_DECODED, f, low):
        hits.append(("R14", "high", "decodes code and runs it"))
    elif _search(PIPE_TO_SHELL, f, low):
        hits.append(("R14", "medium", "pipes a download into a shell"))
    return tuple(hits)


def text_findings(item: Item) -> list[Finding]:
    if item.kind not in TEXT_RULE_KINDS:
        return []
    key = item_key(item)
    seen: set[str] = set()
    out: list[Finding] = []
    for rel, hits in item.file_hits:
        for rule, sev, msg in hits:
            if rule not in seen:  # one finding per rule per item, naming the first file
                seen.add(rule)
                out.append(Finding(rule, sev, key, f"{msg} ({rel})", file=rel))

    # R12: hidden folders, binaries or archives shipped inside a skill, command or agent.
    if item.kind in ("skill", "command", "agent"):
        for f in item.files:
            parts = PurePosixPath(f.path).parts
            if "node_modules" in parts or "__pycache__" in parts:
                continue
            suffix = PurePosixPath(f.path).suffix.lower()
            dotdir = next((p for p in parts[:-1] if p.startswith(".") and p not in OK_DOTDIRS), None)
            if dotdir:
                out.append(Finding("R12", "medium", key, f"ships a hidden folder ({dotdir}/)"))
                break
            if suffix in BINARY_SUFFIXES or suffix in ARCHIVE_SUFFIXES:
                what = "a binary" if suffix in BINARY_SUFFIXES else "an archive"
                out.append(Finding("R12", "medium", key, f"ships {what} ({f.path})"))
                break
    return sorted(out, key=lambda f: int(f.rule[1:]))
