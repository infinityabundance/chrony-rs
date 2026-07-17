#!/usr/bin/env python3
"""Fix the root_readme "What exists today" section to use a link instead of inline list."""
with open('xtask/src/generate.rs', 'r') as f:
    lines = f.readlines()

# Find the lines from "What exists today" to just before OTHER_SURFACES
start_idx = None
end_idx = None
for i, line in enumerate(lines):
    if '## What exists today' in line:
        start_idx = i
    if 's.push_str(OTHER_SURFACES);' in line and start_idx is not None:
        end_idx = i
        break

if start_idx and end_idx:
    print(f"Replacing lines {start_idx+1}-{end_idx}")
    # Build the replacement
    indent = '    '
    replacement = [
        f'{indent}s.push_str(&format!(\n',
        f'{indent}    "## What exists today\\n\\n\\\n',
        f'{indent}    ### Fully ported chrony {{ver}} translation units ({{}})\\n\\n\\\n',
        f'{indent}    Every function in each unit has a court-backed counterpart — differential-tested\\n\\\n',
        f'{indent}    against the **real compiled C** and/or protocol-spec vectors.\\n\\\n',
        f'{indent}    The full per-file breakdown with notes is in the\\n\\\n',
        f'{indent}    [generated ported modules list](docs/generated/ported-modules.md).\\n\\\n',
        f'{indent}    See the [port-parity matrix](docs/generated/port-parity.md) for the\\n\\\n',
        f'{indent}    file-level status of all 70 chrony C files, and the\\n\\\n',
        f'{indent}    [per-function gap view](docs/generated/port-parity-functions.md) for\\n\\\n',
        f'{indent}    individual C function coverage.\\n\\n",\n',
        f'{indent}    full.len()\n',
        f'{indent}));\n',
    ]
    lines[start_idx:end_idx] = replacement
    print("  Replaced with link to ported-modules.md")
else:
    print(f"Could not find: start={start_idx}, end={end_idx}")

with open('xtask/src/generate.rs', 'w') as f:
    f.writelines(lines)
print("Done")
