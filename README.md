# ScorecardTF-Dashboard

A Streamlit-based interactive dashboard for scoring domain security across TLD registries, built for the **CENTR Security Scorecard Task Force**.

---

## What Is This Tool?

The **Security Scorecard Architect** is a browser-based tool that lets analysts:

1. Define a hierarchical set of security tests (items → sub-scores → categories)
2. Map each test to a column in a domain scan CSV file
3. Run vectorised scoring across thousands of domains in seconds
4. Explore results through charts, tables, and per-item pass rates
5. Export scored results and configurations for reporting

The scoring framework is based on the official specification:
> *Domain Security Scorecard – Selected Cases v02 (10 Apr 2026)*, CENTR Security Scorecard Task Force

---

## What Does It Do?

### Section 1 — Configure Hierarchy, Weights & Mappings

An editable table where analysts define every security test. Each row is one test item with the following fields:

| Field | Purpose |
|---|---|
| Control ID | Reference from the spec (e.g. `DE.25`, `W.3.1`) |
| Main Category | Top-level group: Domain Security · Mail Security · Web Security |
| Sub Security Score | Sub-group within a category (e.g. DMARC Score, TLS Security) |
| Item | Human-readable test name |
| Description | What the test checks and how it is evaluated |
| Weight | Points awarded when the item passes |
| CSV Column | Exact column name in the domain scan CSV |
| Match Type | How the CSV value is evaluated (see Match Types below) |
| Expected Value | The target string or threshold to match against |
| Scoring Formula | Score distribution when partially met (see Scoring Formulas below) |
| Requirement Level | `Required` (mandatory baseline) or `Recommended` (best practice) |

### Section 2 — Security Mindmap (Visual Flow)

A **Sankey diagram** showing how individual test items roll up through sub-scores into categories and a total score. Node widths are proportional to weight.

```
Items → Sub-Scores → Main Categories → Total Score
```

### Section 3 — Weight Distribution

Summary metrics (total weight, number of categories, total items) plus a table showing each category's share of the total weight budget.

### Section 4 — Load Domain Scan Data

Upload a domain scan CSV file. The tool validates that mapped CSV columns are present and shows a 5-row preview.

### Section 5 — Scoring Results

Once scoring is run, results are presented across three tabs:

| Tab | Content |
|---|---|
| Score Distribution | Bar chart of average score per sub-score, coloured by category. Score-band summary table (Critical / Poor / Fair / Good / Excellent). |
| Domain Scores | Per-domain table sorted by total score. Cells colour-coded with traffic-light colours based on score. |
| Item Pass Rates | Per-item summary: Pass, Fail, N/A counts and pass-rate percentage. |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Session State                             │
│  sec_data (rule list)  ·  domain_bytes  ·  score_results   │
└────────────┬───────────────────┬────────────────────────────┘
             │                   │
     ┌───────▼──────┐   ┌────────▼────────┐
     │  Data Editor │   │   load_csv()    │
     │  (Section 1) │   │  @cache_data    │
     └───────┬──────┘   └────────┬────────┘
             │                   │
             │         ┌─────────▼──────────┐
             └────────►│  compute_scores()  │
                        │   @cache_data      │
                        │                    │
                        │  per-item pass/pts │
                        │  per-sub-score %   │
                        │  per-category %    │
                        │  Total Score %     │
                        └─────────┬──────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │       Results Display       │
                    │  Distribution · Table · Items│
                    └─────────────┬──────────────┘
                                  │
                              Export CSV / JSON
```

---

## Scoring Logic

### Match Types

| Type | Behaviour |
|---|---|
| `boolean` | Pass if value is `True`, `1`, or `yes` (case-insensitive) |
| `contains` | Pass if CSV value contains the expected string (case-insensitive) |
| `exact` | Pass if CSV value exactly equals the expected string |
| `not_contains` | Pass if CSV value does NOT contain the expected string |
| `count_gte` | Pass if whitespace-token count of value ≥ integer threshold |
| `bool_flag` | Pass if numeric representation of value > 0 |

### Scoring Formulas

| Formula | Description |
|---|---|
| `binary (0/100)` | Full points or zero — no partial credit |
| `0/50/100` | Three-tier: absent / partial / full (e.g. MTA-STS testing vs enforce) |
| `0/25/75/100` | Four-tier: absent / weak / moderate / strong (e.g. DMARC p= level) |
| `0/75/100` | Three-tier: absent / sufficient / full (e.g. SPF -all vs ~all) |
| `tiered` | Multi-level grading defined per test (e.g. TLS version ladder) |

> **Note:** The current scoring engine applies binary pass/fail for all match types. The `Scoring Formula` field documents the intended tiered behaviour for future implementation.

### N/A Sentinel Detection

Scanner failure values are excluded from both numerator and denominator so domains are not penalised for missing scan data:

```
"no answer" · "timeout" · "no existing query name" · "nan" · "none" · ""
```

Values starting with `"error "` or containing `"error fetching"` are also treated as N/A.

### Traffic-Light Score Bands

| Score | Rating | Colour |
|---|---|---|
| ≥ 80% | Excellent / Very Good | Green |
| ≥ 60% | Good | Yellow |
| ≥ 40% | Fair | Orange |
| 0–39% | Poor / Critical | Red |

---

## Default Test Inventory

27 test items sourced from the CENTR spec, organised into three main categories:

### Domain Security
| Control ID | Sub-Score | Item |
|---|---|---|
| DE.21 | DNSSEC Score | DS Record Existence |
| DE.22 | DNSSEC Score | DNSKEY Record Existence |
| DE.23 | DNSSEC Score | DS DNSKEY Matching |

### Mail Security
| Control ID | Sub-Score | Item |
|---|---|---|
| DE.24 | DKIM Score | DKIM Record Existence |
| DE.25 | DMARC Score | DMARC Record Existence |
| DE.26 | DMARC Score | DMARC Policy |
| DE.27 | SPF Score | SPF Record Existence |
| DE.28 | SPF Score | SPF Policy |
| ES.6 | Advanced Mail Security | MTA-STS Policy Mode |
| ES.7 | Advanced Mail Security | TLS Reporting (TLS-RPT) |
| ES.8 | Advanced Mail Security | Verified Logo in Emails (BIMI) |
| T.4.1 | TLS Security (Mail) | STARTTLS Available |
| T.4.2 | TLS Security (Mail) | TLS Version (Mail) |
| T.4.7 | TLS Security (Mail) | TLS Compression Disabled |
| T.4.8 | TLS Security (Mail) | Secure Renegotiation |
| T.5.3 | TLS Security (Mail) | Certificate Signature (Mail) |
| T.6.1 | TLS Security (Mail) | DANE TLSA Existence |
| T.2.3 | DNSSEC Score (Mail) | Mail Server DNSSEC Existence |
| T.2.4 | DNSSEC Score (Mail) | Mail Server DNSSEC Validity |

### Web Security
| Control ID | Sub-Score | Item |
|---|---|---|
| W.3.1 | HTTPS/TLS Security | HTTPS Availability |
| W.3.2 | HTTPS/TLS Security | HTTPS Redirect |
| W.3.4 | HTTPS/TLS Security | HSTS Header |
| W.4.1 | HTTPS/TLS Security | TLS Version (Web) |
| W.6.2 | Security Headers | X-Content-Type-Options Header |
| W.6.3 | Security Headers | Content-Security-Policy Header |
| W.6.4 | Security Headers | Referrer-Policy Header |
| ES.11 | Security Contact | Security Contact File (security.txt) |
| W.CAA | CAA Records | CAA Record Existence |

---

## Usage Instructions

### Prerequisites

```bash
pip install streamlit pandas plotly
```

### Running the App

```bash
cd ScorecardTF-Dashboard
streamlit run app.py
```

Or via Docker Compose (see `docker-compose.yml` in the project root):

```bash
docker compose up
```

### Workflow

```
1. Open the app in your browser (default: http://localhost:8501)

2. [Optional] Edit the rules table:
   - Adjust weights, CSV column mappings, match types
   - Add or remove test items using the dynamic table rows
   - Export the configuration as JSON for reuse

3. [Optional] Import a saved configuration:
   - Use "Import Rules JSON" in the sidebar
   - Older JSON files are auto-upgraded with missing fields

4. Upload your domain scan CSV:
   - File must contain a column named "input_url" (or use the first column as domain identifier)
   - Mapped CSV columns that are missing from the file will trigger a warning

5. Click "▶ Run Scoring"

6. Explore results:
   - Score Distribution tab — overall picture, averages per sub-score
   - Domain Scores tab — per-domain breakdown with traffic-light colouring
   - Item Pass Rates tab — identify which tests most domains fail

7. Export:
   - Summary CSV — domain + all score columns
   - Full CSV — adds per-item pass/fail columns
   - Rules JSON — current configuration for later reuse
```

### Sidebar Controls

| Control | Effect |
|---|---|
| Import Rules JSON | Load a previously exported rule set; missing fields are filled with defaults |
| Reset to Defaults | Restore the built-in 27-item rule set and clear any loaded scan data |

---

## Known Bugs

| # | Description | Workaround |
|---|---|---|
| B-01 | Tiered scoring formulas (DMARC policy levels, SPF ~all vs -all, TLS version ladder) are documented in the `Scoring Formula` field but the engine applies binary pass/fail only. Partial scores are not computed. | Adjust weights to approximate relative importance until tiered scoring is implemented. |
| B-02 | Several tests (MTA-STS, TLS-RPT, BIMI, DANE, HSTS, Referrer-Policy, security.txt) have no corresponding column in the current `.se` scan CSV. They are always scored as N/A and excluded from the denominator. | Map the CSV Column field once the scanner produces those columns. |
| B-03 | DNSSEC tests DE.21/DE.22/DE.23 all map to `dns_has_RRSIG`, which only confirms RRSIG presence, not DS record existence or DS↔DNSKEY matching. Scores for these three items are currently identical. | Requires scanner to provide separate `dns_has_DS` and `dns_has_DNSKEY` columns. |
| B-04 | Pandas Styler rendering is capped at a computed cell count. The `styler.render.max_elements` option is set dynamically at render time, which may cause a brief performance pause on very large datasets (> 50 000 domains). | No action needed; the limit is set automatically. |
| B-05 | The score-band summary table (under Score Distribution) double-counts domains that score exactly 100% because the last band uses an inclusive upper bound. | Cosmetic issue only; totals still sum to the correct domain count. |

---

## Feature Requirements

### High Priority

| ID | Feature | Description |
|---|---|---|
| FR-01 | Tiered scoring engine | Implement the `Scoring Formula` field in `compute_scores()`. Map CSV values to partial point awards: e.g. DMARC `p=reject`→100, `p=quarantine`→75, `p=none`→25, absent→0. |
| FR-02 | Per-domain drill-down | Clicking a domain in the Domain Scores table expands a detail panel showing every item's raw CSV value, pass/fail result, and points earned. |
| FR-03 | Missing CSV columns scanner | Auto-detect column name variations (case, underscores, whitespace) and suggest closest matches when a mapped column is not found in the uploaded file. |

### Medium Priority

| ID | Feature | Description |
|---|---|---|
| FR-04 | Trend comparison | Upload two scan CSV files (e.g. April vs October) and show score delta per domain and per sub-score. |
| FR-05 | Domain filter & search | Search bar and category/score-band filters on the Domain Scores table to focus on subsets of domains. |
| FR-06 | Weighted category override | Allow the overall weight of a Main Category to be set independently of the sum of its items, enabling normalised 0–100 category scores without adjusting individual items. |
| FR-07 | PDF report export | Generate a printable summary report (PDF or HTML) with the score distribution chart, score-band table, and top/bottom 10 domains. |

### Low Priority / Future

| ID | Feature | Description |
|---|---|---|
| FR-08 | DANE / HSTS / MTA-STS scanner integration | Add scanner support for the currently unmapped test items so all 27 rules contribute to scoring. |
| FR-09 | Multi-TLD comparison | Upload scan files from multiple TLD registries and compare average scores side-by-side on a shared axis. |
| FR-10 | Rule version history | Track changes to the rule set over time (git-style diff) so analysts can audit why scores changed between runs. |
| FR-11 | Configurable score bands | Allow the Critical / Poor / Fair / Good / Excellent thresholds to be adjusted from the sidebar rather than being hardcoded. |

---

## File Structure

```
ScorecardTF-Dashboard/
├── app.py               # Main Streamlit application
├── README.md            # This file
└── docker-compose.yml   # Container deployment

Data/
└── final_scorecardTF_domains_for_se_2026-04-09.csv   # .se domain scan results

Docs/
└── Domain Security Scorecard - Selected Cases v02 (10 Apr 2026).pdf   # Spec

Configs/
└── 2026-01-19T14-24_export.csv   # Previous baseline configuration

Old/
└── app_v3.py            # Earlier prototype (Sankey only, no scoring)
```

---

## Reference

- **Specification:** *Domain Security Scorecard – Selected Cases v02*, CENTR Security Scorecard Task Force, 10 April 2026
- **Framework:** [Streamlit](https://streamlit.io) · [Plotly](https://plotly.com/python/) · [pandas](https://pandas.pydata.org)
- **Maintained by:** CENTR Security Scorecard Task Force
