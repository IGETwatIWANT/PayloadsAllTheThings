"""
Payload parser for PayloadsAllTheThings repository.

Parses the markdown files and Intruder payload lists from the
PayloadsAllTheThings repository into structured data.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Maps directory names to canonical category names
CATEGORY_MAP = {
    "SQL Injection": "sqli",
    "XSS Injection": "xss",
    "Command Injection": "cmdi",
    "Server Side Request Forgery": "ssrf",
    "Server Side Template Injection": "ssti",
    "Directory Traversal": "path_traversal",
    "File Inclusion": "lfi_rfi",
    "XXE Injection": "xxe",
    "LDAP Injection": "ldap",
    "NoSQL Injection": "nosqli",
    "XPATH Injection": "xpath",
    "XSLT Injection": "xslt",
    "CRLF Injection": "crlf",
    "CSV Injection": "csvi",
    "GraphQL Injection": "graphql",
    "JSON Web Token": "jwt",
    "CORS Misconfiguration": "cors",
    "Cross-Site Request Forgery": "csrf",
    "Open Redirect": "open_redirect",
    "SAML Injection": "saml",
    "Insecure Deserialization": "deserialization",
    "Upload Insecure Files": "file_upload",
    "Request Smuggling": "request_smuggling",
    "Prototype Pollution": "prototype_pollution",
    "OAuth Misconfiguration": "oauth",
    "Race Condition": "race_condition",
    "Server Side Include Injection": "ssi",
    "Mass Assignment": "mass_assignment",
    "HTTP Parameter Pollution": "hpp",
    "Type Juggling": "type_juggling",
    "Clickjacking": "clickjacking",
    "DOM Clobbering": "dom_clobbering",
    "DNS Rebinding": "dns_rebinding",
    "Insecure Direct Object References": "idor",
    "Web Cache Deception": "cache_deception",
    "Zip Slip": "zip_slip",
    "LaTeX Injection": "latex",
    "Prompt Injection": "prompt_injection",
    "Account Takeover": "account_takeover",
    "Dependency Confusion": "dependency_confusion",
}


@dataclass
class ParsedPayload:
    """A single parsed payload with metadata."""
    payload: str
    category: str
    subcategory: str = ""
    source_file: str = ""
    tags: list[str] = field(default_factory=list)
    context: str = ""
    encoding: str = "raw"


@dataclass
class ParsedCategory:
    """A parsed vulnerability category with all its data."""
    name: str
    canonical_name: str
    description: str = ""
    tools: list[str] = field(default_factory=list)
    methodology_sections: list[dict[str, str]] = field(default_factory=list)
    payloads: list[ParsedPayload] = field(default_factory=list)
    intruder_payloads: dict[str, list[str]] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    sub_documents: list[str] = field(default_factory=list)


class PayloadParser:
    """
    Parses the PayloadsAllTheThings repository structure into
    structured payload data.
    """

    def __init__(self, repo_path: str | Path):
        self._repo_path = Path(repo_path)

    def parse_all(self) -> list[ParsedCategory]:
        """Parse all vulnerability categories in the repository."""
        categories = []

        for dir_path in sorted(self._repo_path.iterdir()):
            if not dir_path.is_dir():
                continue
            if dir_path.name.startswith(("_", ".")):
                continue
            if dir_path.name in ("Methodology and Resources", "Encoding Transformations"):
                continue

            canonical = CATEGORY_MAP.get(dir_path.name, dir_path.name.lower().replace(" ", "_"))
            category = self._parse_category(dir_path, canonical)
            if category.payloads or category.intruder_payloads:
                categories.append(category)
                logger.info(f"Parsed {dir_path.name}: {len(category.payloads)} inline payloads, "
                           f"{sum(len(v) for v in category.intruder_payloads.values())} intruder payloads")

        return categories

    def parse_category(self, category_name: str) -> ParsedCategory | None:
        """Parse a single category by directory name."""
        dir_path = self._repo_path / category_name
        if not dir_path.is_dir():
            return None
        canonical = CATEGORY_MAP.get(category_name, category_name.lower().replace(" ", "_"))
        return self._parse_category(dir_path, canonical)

    def _parse_category(self, dir_path: Path, canonical_name: str) -> ParsedCategory:
        """Parse a single category directory."""
        category = ParsedCategory(
            name=dir_path.name,
            canonical_name=canonical_name,
        )

        # Parse README.md
        readme = dir_path / "README.md"
        if readme.exists():
            self._parse_readme(readme, category)

        # Parse additional markdown files
        for md_file in sorted(dir_path.glob("*.md")):
            if md_file.name != "README.md":
                category.sub_documents.append(md_file.name)
                self._parse_sub_document(md_file, category)

        # Parse Intruder payloads
        intruder_dirs = [dir_path / "Intruder", dir_path / "Intruders"]
        for intruder_dir in intruder_dirs:
            if intruder_dir.is_dir():
                self._parse_intruder_dir(intruder_dir, category)

        return category

    def _parse_readme(self, readme_path: Path, category: ParsedCategory) -> None:
        """Parse a README.md for payloads and methodology."""
        content = readme_path.read_text(errors="replace")

        # Extract description (first paragraph)
        lines = content.split("\n")
        desc_lines = []
        in_desc = False
        for line in lines:
            if line.startswith("# "):
                in_desc = True
                continue
            if in_desc:
                if line.startswith("## ") or line.startswith("- ["):
                    break
                if line.strip():
                    desc_lines.append(line.strip())
        category.description = " ".join(desc_lines)

        # Extract tools
        tools_match = re.search(r'## Tools?\s*\n(.*?)(?=\n## |\Z)', content, re.DOTALL)
        if tools_match:
            for line in tools_match.group(1).split("\n"):
                tool_match = re.match(r'\*\s*\[([^\]]+)\]', line)
                if tool_match:
                    category.tools.append(tool_match.group(1))

        # Extract code block payloads
        self._extract_code_payloads(content, category, str(readme_path))

        # Extract references
        refs_match = re.search(r'## References?\s*\n(.*?)(?=\n## |\Z)', content, re.DOTALL)
        if refs_match:
            for line in refs_match.group(1).split("\n"):
                url_match = re.search(r'https?://[^\s\)]+', line)
                if url_match:
                    category.references.append(url_match.group(0))

    def _parse_sub_document(self, md_path: Path, category: ParsedCategory) -> None:
        """Parse additional markdown files for payloads."""
        content = md_path.read_text(errors="replace")
        self._extract_code_payloads(content, category, str(md_path))

    def _extract_code_payloads(self, content: str, category: ParsedCategory, source: str) -> None:
        """Extract payloads from markdown code blocks."""
        # Find code blocks
        code_blocks = re.findall(r'```(?:\w+)?\s*\n(.*?)```', content, re.DOTALL)
        for block in code_blocks:
            lines = [l.strip() for l in block.strip().split("\n") if l.strip()]
            for line in lines:
                # Skip comments and pure descriptions
                if line.startswith("#") and not line.startswith("#!/"):
                    continue
                if len(line) > 5:  # Skip very short lines
                    category.payloads.append(ParsedPayload(
                        payload=line,
                        category=category.canonical_name,
                        source_file=source,
                    ))

        # Also extract inline code payloads from specific patterns
        inline_payloads = re.findall(r'`([^`]{5,200})`', content)
        for payload in inline_payloads:
            # Filter out things that look like payloads vs descriptions
            if any(c in payload for c in ("'", '"', "<", ">", "(", "{", "=", "/", "\\", "|", ";", "&")):
                category.payloads.append(ParsedPayload(
                    payload=payload,
                    category=category.canonical_name,
                    source_file=source,
                    context="inline",
                ))

    def _parse_intruder_dir(self, intruder_dir: Path, category: ParsedCategory) -> None:
        """Parse Burp Intruder payload files."""
        for payload_file in sorted(intruder_dir.iterdir()):
            if payload_file.is_file() and payload_file.suffix in (".txt", ""):
                try:
                    lines = payload_file.read_text(errors="replace").strip().split("\n")
                    payloads = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
                    if payloads:
                        category.intruder_payloads[payload_file.name] = payloads
                except Exception as exc:
                    logger.warning(f"Failed to parse {payload_file}: {exc}")
