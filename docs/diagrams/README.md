<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Diagrams

Rendered, presentation-quality views of the system. Each `.svg` is generated
from the `.d2` source beside it — the `.d2` is the editable source of truth, the
`.svg` is the committed render that GitHub and the docs display inline.

| Diagram | Source | Shows |
| --- | --- | --- |
| `01-big-picture.svg` | `01-big-picture.d2` | The guest, this binary, the Envoy egress edge, the REST filestore, and backend storage, with the trust zones. |
| `02-file-path.svg` | `02-file-path.d2` | A file's read and write paths through the Envoy egress edge, including the VFS cache and throttle behaviour. |
| `03-package-map.svg` | `03-package-map.d2` | The repository's packages and who calls whom, down to the single egress. |
| `04-setup.svg` | `04-setup.d2` | The four steps to build and run the binary against a broker. |

These complement the Mermaid diagrams inline in [`../architecture.md`](../architecture.md):
the Mermaid blocks are the low-ceremony, diff-friendly source that lives with the
prose; these SVGs are the polished standalone renders for a first read.

## Regenerating

The renders are produced with [D2](https://d2lang.com):

```sh
# once: go install oss.terrastruct.com/d2@latest   (or see d2lang.com/tour/install)
for f in docs/diagrams/*.d2; do
  d2 "$f" "${f%.d2}.svg"
done
```

Edit the `.d2`, re-render, and commit both. Do not hand-edit an `.svg`; it will
be overwritten on the next render.
