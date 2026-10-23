"""Join hard-wrapped lines of the CHANGELOG section: GitHub renders single
newlines in release notes as line breaks. Code blocks, headings, list
items and tables are kept as they are."""
import sys
out, code = [], False
for line in open(sys.argv[1]):
    line = line.rstrip("\n")
    if line.startswith("```"):
        code = not code
        out.append(line)
        continue
    prev = out[-1] if out else ""
    starts_block = line.startswith(("#", "- ", "* ", "|")) or not line.strip()
    if code or starts_block or not prev.strip() or prev.startswith(("#", "```", "|")):
        out.append(line)
    else:
        out[-1] = prev + " " + line.strip()
print("\n".join(out))
