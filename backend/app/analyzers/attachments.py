"""
Attachment analyzer: are there files that could run code on the user's machine?

We only look at file names and types; the add-on never sends file contents.
"""
import re

from app.analyzers.base import Finding
from app.schemas import EmailInput

# Files Windows will execute directly when double-clicked
EXECUTABLE = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf",
    "wsh", "ps1", "msi", "hta", "jar", "lnk", "cpl", "reg", "dll", "appx",
}
# Office files that can contain macros (code that runs inside Word/Excel)
MACRO_OFFICE = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppsm"}
# Disk images: opening one mounts it, which bypasses some Windows download warnings
DISK_IMAGE = {"iso", "img", "vhd", "vhdx"}
# HTML/SVG files open in the browser and can show a fake login page offline
WEB_PAGE = {"html", "htm", "shtml", "svg", "xhtml"}
# Archives hide their contents from scanners that don't unpack them
ARCHIVE = {"zip", "rar", "7z", "gz", "tar", "ace", "cab"}
# Extensions attackers put *before* the real one to look harmless
DECOY = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "ppt", "pptx"}

# Unicode control characters that reverse or reorder how text is displayed.
# "invoice‮fdp.exe" is shown as "invoiceexe.pdf".
BIDI_CONTROLS = re.compile("[‎‏‪-‮⁦-⁩]")


def _extensions(name: str) -> list[str]:
    """'Invoice.PDF.exe ' -> ['pdf', 'exe']. Windows ignores trailing dots and spaces."""
    clean = BIDI_CONTROLS.sub("", name).strip().rstrip(". ").lower()
    parts = clean.split(".")
    return parts[1:] if len(parts) > 1 else []


def analyze(email: EmailInput) -> list[Finding]:
    hits: dict[str, list[str]] = {
        "bidi": [], "double": [], "exe": [], "macro": [], "web": [], "image": [], "archive": [],
    }

    for attachment in email.attachments:
        name = attachment.name
        exts = _extensions(name)
        last = exts[-1] if exts else ""
        shown = BIDI_CONTROLS.sub("", name)

        if BIDI_CONTROLS.search(name):
            hits["bidi"].append(shown)
        if last in EXECUTABLE and len(exts) >= 2 and exts[-2] in DECOY:
            hits["double"].append(shown)
        elif last in EXECUTABLE:
            hits["exe"].append(shown)
        if last in MACRO_OFFICE:
            hits["macro"].append(shown)
        if last in WEB_PAGE:
            hits["web"].append(shown)
        if last in DISK_IMAGE:
            hits["image"].append(shown)
        if last in ARCHIVE:
            hits["archive"].append(shown)

    findings: list[Finding] = []

    def add(key: str, signal: str, points: int, message: str) -> None:
        names = list(dict.fromkeys(hits[key]))
        if names:
            more = f" (and {len(names) - 1} more)" if len(names) > 1 else ""
            findings.append(Finding(signal, points, f"{message}: '{names[0]}'{more}."))

    add("bidi", "attachment_hidden_extension", 40,
        "An attachment's name uses hidden characters that disguise its real file type")
    add("double", "attachment_double_extension", 45,
        "An attachment pretends to be a document but is actually a program")
    add("exe", "attachment_executable", 40, "An attachment is a program that can run on your computer")
    add("macro", "attachment_macro_office", 30, "An attachment is an Office file that can contain macros (hidden code)")
    add("web", "attachment_web_page", 25, "An attachment is a web page file, often used for fake login pages")
    add("image", "attachment_disk_image", 25, "An attachment is a disk image, a format used to slip programs past security warnings")
    add("archive", "attachment_archive", 10, "An attachment is a compressed archive whose contents can't be checked here")
    return findings
