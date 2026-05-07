#!/usr/bin/env python3
"""Render a non-optimal cluster dump as a diagram.

Usage:
    visualize_nonoptimal_dump.py <dump.json>                  # markdown to stdout
    visualize_nonoptimal_dump.py <dump.json> --svg out.svg    # static SVG (no JS)
    visualize_nonoptimal_dump.py <dump.json> --html out.html  # standalone HTML+mermaid
    visualize_nonoptimal_dump.py <dump.json> --dot out.dot    # graphviz source

For each cluster in the dump, emits a graph with:
  - one node per tx, labeled with lin index, txid prefix, fee, weight, sat/vB
  - edges from parent_lin -> child
  - nodes coloured by chunk membership (if quality >= ACCEPTABLE),
    otherwise each tx gets its own colour to make order visible
  - red border on any tx whose wtxid appears in context.added_wtxids
    (so for an "apply" trigger you can spot the addition that tripped the event)
"""
import argparse
import html
import json
import os
import subprocess
import sys

# Distinct, soft fills cycled per chunk.
CHUNK_COLORS = [
    "#fde68a", "#bbf7d0", "#bfdbfe", "#fbcfe8",
    "#fed7aa", "#ddd6fe", "#fecaca", "#a7f3d0",
]


def chunks_of(cluster):
    """Group txs into chunks. A "chunk" is a maximal run of consecutive
    lin_index entries sharing the same (chunk_fee, chunk_size). When
    chunk_fee/chunk_size are 0 (cluster quality < ACCEPTABLE) every tx
    is its own chunk so the colour cycle still gives visual separation."""
    chunks = []
    cur, cur_key = [], None
    for t in cluster["txs"]:
        key = (t["chunk_fee"], t["chunk_size"])
        if key == (0, 0):
            if cur:
                chunks.append(cur)
                cur, cur_key = [], None
            chunks.append([t["lin_index"]])
            continue
        if key == cur_key:
            cur.append(t["lin_index"])
        else:
            if cur:
                chunks.append(cur)
            cur, cur_key = [t["lin_index"]], key
    if cur:
        chunks.append(cur)
    return chunks


def render_cluster_mermaid(cluster, highlight_wtxids=()):
    out = ["graph TD"]
    txs = cluster["txs"]

    chunks = chunks_of(cluster)
    chunk_of = {i: ci for ci, idxs in enumerate(chunks) for i in idxs}

    for t in txs:
        lin = t["lin_index"]
        feerate = t["fee_sats"] / max(t["vsize"], 1)
        # <br/> is preserved by mermaid inside quoted node labels.
        label = (
            f"L{lin} {t['txid'][:8]}<br/>"
            f"{t['fee_sats']} sat / {t['vsize']} vB<br/>"
            f"{feerate:.1f} sat/vB · w={t['weight']}"
        )
        # Quote with double-quotes; Mermaid escapes inner content.
        out.append(f'  L{lin}["{label}"]')

    for t in txs:
        for p in t["parents_lin"]:
            out.append(f"  L{p} --> L{t['lin_index']}")

    for ci, idxs in enumerate(chunks):
        color = CHUNK_COLORS[ci % len(CHUNK_COLORS)]
        for i in idxs:
            out.append(f"  style L{i} fill:{color},stroke:#475569")

    for t in txs:
        if t.get("wtxid") in highlight_wtxids:
            out.append(
                f"  style L{t['lin_index']} stroke:#dc2626,stroke-width:3px"
            )

    return "\n".join(out)


def render_dump_markdown(d):
    out = []
    ctx = d.get("context") or {}
    added = set(ctx.get("added_wtxids") or [])

    out.append(f"# Non-optimal cluster dump — `{d['trigger']}`")
    out.append("")
    out.append(f"- ts_unix: `{d['ts_unix']}` ({d['ts_unix_ns']} ns)")
    if "config" in d:
        c = d["config"]
        out.append(
            f"- config: `acceptable_cost={c['acceptable_cost']}` "
            f"`post_change_cost={c['post_change_cost']}` "
            f"`max_cluster_count={c['max_cluster_count']}` "
            f"`max_cluster_size_vbytes={c['max_cluster_size_vbytes']}` "
            f"`bytes_per_sigop={c['bytes_per_sigop']}`"
        )
    if added:
        out.append("- added wtxids (red border): "
                   + ", ".join(f"`{w[:12]}…`" for w in sorted(added)))
    if ctx.get("removed_txids"):
        out.append("- removed txids: "
                   + ", ".join(f"`{t[:12]}…`" for t in ctx["removed_txids"]))
    if "block_height" in ctx:
        out.append(f"- block_height: `{ctx['block_height']}`  "
                   f"block_tx_count: `{ctx.get('block_tx_count', '?')}`")
    out.append("")

    for ci, c in enumerate(d["non_optimal_clusters"]):
        out.append(
            f"## Cluster {ci}: seq=`{c['sequence']}` "
            f"quality=`{c['quality']}` tx_count=`{c['tx_count']}`"
        )
        out.append("")
        out.append("```mermaid")
        out.append(render_cluster_mermaid(c, highlight_wtxids=added))
        out.append("```")
        out.append("")

    return "\n".join(out)


HTML_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 1100px;
         margin: 2em auto; padding: 0 1em; color: #1f2937; }}
  h1, h2 {{ border-bottom: 1px solid #e5e7eb; padding-bottom: .2em; }}
  ul {{ line-height: 1.5; }}
  code {{ background: #f3f4f6; padding: 1px 4px; border-radius: 3px; }}
  pre.mermaid {{ background: #fff; border: 1px solid #e5e7eb;
                 padding: 1em; border-radius: 6px; }}
</style>
</head><body>
{body}
<script>mermaid.initialize({{startOnLoad: true, theme: 'default'}});</script>
</body></html>
"""


def render_dump_html(d, title):
    ctx = d.get("context") or {}
    added = set(ctx.get("added_wtxids") or [])

    parts = [f"<h1>Non-optimal cluster dump — <code>{html.escape(d['trigger'])}</code></h1>"]
    parts.append("<ul>")
    parts.append(
        f"<li>ts_unix: <code>{d['ts_unix']}</code> "
        f"({d['ts_unix_ns']} ns)</li>"
    )
    if "config" in d:
        c = d["config"]
        parts.append(
            "<li>config: "
            + " · ".join(
                f"<code>{k}={v}</code>" for k, v in c.items()
            )
            + "</li>"
        )
    if added:
        parts.append(
            "<li>added wtxids (red border): "
            + ", ".join(f"<code>{html.escape(w[:12])}…</code>" for w in sorted(added))
            + "</li>"
        )
    if ctx.get("removed_txids"):
        parts.append(
            "<li>removed txids: "
            + ", ".join(f"<code>{html.escape(t[:12])}…</code>" for t in ctx["removed_txids"])
            + "</li>"
        )
    if "block_height" in ctx:
        parts.append(
            f"<li>block_height: <code>{ctx['block_height']}</code> · "
            f"block_tx_count: <code>{ctx.get('block_tx_count', '?')}</code></li>"
        )
    parts.append("</ul>")

    for ci, c in enumerate(d["non_optimal_clusters"]):
        parts.append(
            f"<h2>Cluster {ci}: seq=<code>{c['sequence']}</code> "
            f"quality=<code>{c['quality']}</code> "
            f"tx_count=<code>{c['tx_count']}</code></h2>"
        )
        diagram = render_cluster_mermaid(c, highlight_wtxids=added)
        parts.append(f'<pre class="mermaid">{html.escape(diagram)}</pre>')

    return HTML_TEMPLATE.format(title=html.escape(title), body="\n".join(parts))


def render_dump_dot(d):
    """Combined Graphviz DOT — one digraph, one subgraph cluster per
    non-optimal cluster. Render with `dot -Tsvg` (or -Tpng)."""
    ctx = d.get("context") or {}
    added = set(ctx.get("added_wtxids") or [])

    out = ["digraph G {"]
    out.append("  rankdir=TB;")
    out.append("  compound=true;")
    out.append('  node [shape=box, style="filled,rounded", '
               'fontname="monospace", fontsize=10];')
    out.append('  edge [color="#475569"];')

    # Top label with trigger + config + context summary.
    title_lines = [f"trigger: {d['trigger']}",
                   f"ts_unix: {d['ts_unix']}"]
    if "config" in d:
        c = d["config"]
        title_lines.append(
            f"acceptable_cost={c['acceptable_cost']}  "
            f"post_change_cost={c['post_change_cost']}"
        )
        title_lines.append(
            f"max_cluster_count={c['max_cluster_count']}  "
            f"max_cluster_size_vbytes={c['max_cluster_size_vbytes']}"
        )
    if added:
        sample = ", ".join(w[:10] + "…" for w in sorted(added)[:3])
        title_lines.append(f"added wtxids (red border): {sample}")
    if "block_height" in ctx:
        title_lines.append(f"block_height: {ctx['block_height']}")
    title_html = "<br/>".join(html.escape(s) for s in title_lines)
    out.append(f'  graph [label=<{title_html}>, labelloc=t, '
               f'fontname="sans-serif", fontsize=11];')

    for ci, c in enumerate(d["non_optimal_clusters"]):
        prefix = f"c{ci}_"
        chunks = chunks_of(c)
        chunk_of = {i: idx for idx, idxs in enumerate(chunks) for i in idxs}

        out.append(f"  subgraph cluster_{ci} {{")
        out.append(
            f'    label="cluster {ci}: seq={c["sequence"]} '
            f'quality={c["quality"]} tx_count={c["tx_count"]}";'
        )
        out.append('    style="rounded,dashed"; color="#94a3b8"; '
                   'fontname="sans-serif"; fontsize=10; labelloc=b;')

        for t in c["txs"]:
            lin = t["lin_index"]
            feerate = t["fee_sats"] / max(t["vsize"], 1)
            label = (
                f"L{lin}  {t['txid'][:8]}\\n"
                f"{t['fee_sats']} sat / {t['vsize']} vB\\n"
                f"{feerate:.1f} sat/vB · w={t['weight']}"
            )
            color = CHUNK_COLORS[chunk_of[lin] % len(CHUNK_COLORS)]
            attrs = [f'label="{label}"', f'fillcolor="{color}"']
            if t.get("wtxid") in added:
                attrs.append('color="#dc2626"')
                attrs.append("penwidth=3")
            out.append(f'    {prefix}L{lin} [{", ".join(attrs)}];')

        for t in c["txs"]:
            for p in t["parents_lin"]:
                out.append(f"    {prefix}L{p} -> {prefix}L{t['lin_index']};")
        out.append("  }")

    out.append("}")
    return "\n".join(out)


def render_dump_via_dot(d, fmt):
    """Run graphviz `dot` to convert the DOT source to the requested format
    (e.g. 'svg', 'png'). Returns bytes."""
    dot_src = render_dump_dot(d).encode()
    proc = subprocess.run(
        ["dot", f"-T{fmt}"],
        input=dot_src,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode(errors="replace"))
        raise SystemExit(f"dot exited {proc.returncode}")
    return proc.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump", help="path to a cluster_dump_*.json file")
    ap.add_argument("--svg", metavar="OUT",
                    help="write static SVG via graphviz (no JS, opens in any browser)")
    ap.add_argument("--png", metavar="OUT",
                    help="write static PNG via graphviz")
    ap.add_argument("--dot", metavar="OUT",
                    help="write graphviz DOT source")
    ap.add_argument("--html", metavar="OUT",
                    help="write standalone HTML using mermaid (needs network)")
    args = ap.parse_args()

    with open(args.dump) as f:
        d = json.load(f)

    if args.svg:
        with open(args.svg, "wb") as f:
            f.write(render_dump_via_dot(d, "svg"))
        print(f"wrote {args.svg}", file=sys.stderr)
    elif args.png:
        with open(args.png, "wb") as f:
            f.write(render_dump_via_dot(d, "png"))
        print(f"wrote {args.png}", file=sys.stderr)
    elif args.dot:
        with open(args.dot, "w") as f:
            f.write(render_dump_dot(d))
        print(f"wrote {args.dot}", file=sys.stderr)
    elif args.html:
        title = os.path.basename(args.dump)
        out = render_dump_html(d, title)
        with open(args.html, "w") as f:
            f.write(out)
        print(f"wrote {args.html}", file=sys.stderr)
    else:
        print(render_dump_markdown(d))


if __name__ == "__main__":
    main()
