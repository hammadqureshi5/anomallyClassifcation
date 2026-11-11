# FYP Mid-Term Report: AI-Based Autonomous Cyber Defense System

LaTeX source of the mid-term report (preliminary pages and Chapters 1–3). It follows the
official SZABIST "FYP Final Report Overleaf Template (BSAI)".

## Compile in Overleaf
1. Zip this folder, or upload its contents: **New Project → Upload Project**.
2. **Menu → Settings:**
   - **Compiler:** `pdfLaTeX`
   - **Main document:** `main.tex`
   - **TeX Live version:** 2023 or newer
3. Click **Recompile**. Overleaf runs pdfLaTeX → BibTeX → pdfLaTeX automatically, so the
   references, table of contents, list of figures and list of tables are generated.

## Compile locally
```bash
latexmk -pdf main.tex      # or: pdflatex main && bibtex main && pdflatex main && pdflatex main
```
Required packages, all included in TeX Live: geometry, setspace, titlesec, enumitem,
multirow, booktabs, longtable, tabularx, caption, adjustbox, pifont, tikz, hyperref, and
IEEEtran (`IEEEtran.bst`, for references).

## Structure
| Path | Contents |
|---|---|
| `main.tex` | Preamble (copied from the template's `3-Document.tex`) and the input order |
| `pages/` | Title, approval page and declaration, project overview, dedication, acknowledgment, revision history, contents and lists |
| `chapters/` | `Chapter-1*.tex` (Introduction), `Chapter-2*.tex` (Background and Literature Review), `Chapter-3*.tex` (SRS); one file per section, as in the template |
| `references.bib` | IEEE references (BibTeX + `IEEEtran` style); only cited entries are printed |
| `figures/` | Module result figures (PNG). The diagrams are drawn in TikZ inside the chapter files. |
| `assets/` | SZABIST logo from the official template |

## Before submission: items the team must confirm
- **Revision history:** dates and authors for versions 2.x (`pages/Revision-History.tex`).
- **Time frame:** durations for future phases (`chapters/Chapter-3-5.tex`) are estimates.
- **Malware metrics:** check against `models/model_metrics.json` (Malware results table in Section 2.4).
- **Approval page:** names of the FYP Committee Head and Program Manager (`pages/Declaration.tex`).
- **Network Threat Classification author:** assumed to be Muhammad Bilal Khan.
