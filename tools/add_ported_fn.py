#!/usr/bin/env python3
"""Add ported_modules_md function to generate.rs."""
with open('xtask/src/generate.rs', 'r') as f:
    content = f.read()

new_func = r'''
/// Generate the separate ported-modules.md file with the full inline list.
pub fn ported_modules_md(root: &Path) -> String {
    let full: Vec<_> = crate::parity::ported_modules()
        .into_iter()
        .filter(|m| m.full)
        .collect();
    let mut s = String::new();
    s.push_str(HEADER);
    s.push_str(&format!(
        "# Fully ported chrony 4.5 translation units\n\n\
        Every function in each unit has a court-backed counterpart —\n\
        differential-tested against the **real compiled C** and/or protocol-spec\n\
        vectors. This list is generated from the\n\
        [port-parity matrix](port-parity.md).\n\n\
        **Note:** A file being listed here means every function in that chrony\n\
        `.c` file has a corresponding Rust implementation. It does **not** mean\n\
        every function is wired into a running daemon — see\n\
        [`deployment-boundary.md`](../deployment-boundary.md) and\n\
        [`negative-capabilities.md`](../negative-capabilities.md) for what is and\n\
        isn't admitted at daemon level.\n\n"
    ));
    for m in &full {
        s.push_str(&format!("- **`{}`** — {}\n", m.c, m.note));
    }
    s
}
'''

old = 'pub fn facade_readme'
if old in content:
    content = content.replace(old, new_func + '\n' + old, 1)
    with open('xtask/src/generate.rs', 'w') as f:
        f.write(content)
    print('Added ported_modules_md function')
else:
    print('Could not find insertion point (pub fn facade_readme)')
