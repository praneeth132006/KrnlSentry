# Report figures

The figures embedded in [`../KrnlSentry_Project_Report_IEEE.docx`](../KrnlSentry_Project_Report_IEEE.docx).

| File | Figure | Source |
| ---- | ------ | ------ |
| `fig1-architecture.png` | Fig. 1 — kernel/user-space pipeline | `fig1-architecture.mmd` |
| `fig2-reverse-shell-state-machine.png` | Fig. 2 — reverse-shell sequence detector | `fig2-reverse-shell-state-machine.mmd` |
| `fig3-evaluation-order.png` | Fig. 3 — per-event evaluation order | `fig3-evaluation-order.mmd` |
| `fig4-lineage-correlation.png` | Fig. 4 — lineage reconstruction and escalation | `fig4-lineage-correlation.mmd` |
| `fig5-dashboard.png` | Fig. 5 — the live dashboard | screenshot of a real `--dashboard` replay |
| `fig6-verification-layers.png` | Fig. 6 — the four verification layers | `fig6-verification-layers.mmd` |

Every `.png` except the dashboard is generated from the Mermaid source beside it:

```bash
npx -y @mermaid-js/mermaid-cli -b white -s 3 -i fig1-architecture.mmd -o fig1-architecture.png
```

`fig5-dashboard.png` is a screenshot of an actual run, not a mock-up:

```bash
COLUMNS=112 LINES=46 ./bin/krnlsentry --replay testdata/captures/intrusion.jsonl \
  --output /tmp/demo.jsonl --dashboard --color --replay-speed 20
```

Figures for the Markdown report live inline in [`../../REPORT.md`](../../REPORT.md) as Mermaid
blocks, which GitHub renders directly; these rasterised copies exist because
Word cannot render Mermaid.
