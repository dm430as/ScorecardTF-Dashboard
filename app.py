import io
import json

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="Security Scorecard Architect", layout="wide")

REQUIRED_COLS = ["Main Category", "Sub Security Score", "Item", "Value", "Weight", "CSV Column", "Match Type"]
MATCH_TYPES   = ["boolean", "contains", "exact", "not_contains", "count_gte", "bool_flag"]

# Strings that indicate the scanner had no result — not a domain failure
NA_SENTINELS = {"no answer", "timeout", "no existing query name", "nan", "none", ""}

DEFAULT_DATA = [
    {"Main Category": "DNS",  "Sub Security Score": "DNSSEC Integrity", "Item": "Algorithm Type",  "Value": "ECDSA",    "Weight": 25, "CSV Column": "dns_value_RRSIG",  "Match Type": "contains"},
    {"Main Category": "DNS",  "Sub Security Score": "DNSSEC Integrity", "Item": "RRSIG Validity",  "Value": "True",     "Weight": 25, "CSV Column": "dns_has_RRSIG",    "Match Type": "boolean"},
    {"Main Category": "DNS",  "Sub Security Score": "Redundancy",       "Item": "NS Count",        "Value": "2",        "Weight": 50, "CSV Column": "dns_value_NS",      "Match Type": "count_gte"},
    {"Main Category": "Mail", "Sub Security Score": "Authentication",   "Item": "SPF Policy",      "Value": "-all",     "Weight": 30, "CSV Column": "dns_value_TXT",     "Match Type": "contains"},
    {"Main Category": "Mail", "Sub Security Score": "Authentication",   "Item": "DMARC Policy",    "Value": "p=reject", "Weight": 40, "CSV Column": "dns_value_dmarc",   "Match Type": "contains"},
    {"Main Category": "Mail", "Sub Security Score": "Encryption",       "Item": "DANE TLSA",       "Value": "True",     "Weight": 30, "CSV Column": "dns_has_MX",        "Match Type": "boolean"},
    {"Main Category": "Web",  "Sub Security Score": "TLS Config",       "Item": "Protocol Version","Value": "True",     "Weight": 60, "CSV Column": "ssl_enabled",       "Match Type": "boolean"},
    {"Main Category": "Web",  "Sub Security Score": "TLS Config",       "Item": "Cipher Suite",    "Value": "True",     "Weight": 40, "CSV Column": "fx_hcj__secu_tls",  "Match Type": "bool_flag"},
]


# ── Scoring engine ────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def load_csv(data_bytes: bytes) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(data_bytes), low_memory=False)


@st.cache_data(show_spinner=False)
def compute_scores(data_bytes: bytes, rules_json: str) -> pd.DataFrame:
    """
    Score every domain row against the ruleset.
    N/A (scanner failure) items are excluded from the denominator so domains
    are not penalised for missing scan data.
    Returns a results DataFrame with per-item, per-category, and total scores.
    """
    data_df   = pd.read_csv(io.BytesIO(data_bytes), low_memory=False)
    rules_df  = pd.DataFrame(json.loads(rules_json))

    domain_col = "input_url" if "input_url" in data_df.columns else data_df.columns[0]
    results    = pd.DataFrame({"Domain": data_df[domain_col].values})

    item_pts_cols = []
    item_max_cols = []

    for _, rule in rules_df.iterrows():
        item     = rule["Item"]
        col      = str(rule.get("CSV Column", "")).strip()
        match    = str(rule.get("Match Type", "boolean"))
        expected = str(rule.get("Value", ""))
        weight   = float(rule.get("Weight", 0))

        pass_key = f"{item} | pass"
        pts_key  = f"{item} | pts"
        max_key  = f"{item} | max"
        item_pts_cols.append(pts_key)
        item_max_cols.append(max_key)

        if not col or col not in data_df.columns:
            results[pass_key] = None
            results[pts_key]  = float("nan")
            results[max_key]  = float("nan")
            continue

        raw     = data_df[col]
        raw_str = raw.astype(str).str.strip()

        na_mask = (
            raw.isna()
            | raw_str.str.lower().isin(NA_SENTINELS)
            | raw_str.str.lower().str.startswith("error ")
            | raw_str.str.lower().str.contains("error fetching", na=False, regex=False)
        )

        if match == "boolean":
            passed = raw_str.str.lower().isin(["true", "1", "yes"])
        elif match == "contains":
            passed = raw_str.str.lower().str.contains(expected.lower(), regex=False, na=False)
        elif match == "exact":
            passed = raw_str.str.lower() == expected.lower()
        elif match == "not_contains":
            passed = ~raw_str.str.lower().str.contains(expected.lower(), regex=False, na=False)
        elif match == "count_gte":
            try:
                threshold = int(expected)
                passed = raw_str.str.split().str.len().fillna(0) >= threshold
            except ValueError:
                passed = pd.Series(False, index=data_df.index)
        elif match == "bool_flag":
            passed = pd.to_numeric(raw, errors="coerce").fillna(0) > 0
        else:
            passed = pd.Series(False, index=data_df.index)

        pass_result                = passed.astype(object)
        pass_result[na_mask.values] = None

        results[pass_key] = pass_result.values
        results[pts_key]  = [weight if v is True else (0.0 if v is False else float("nan")) for v in pass_result]
        results[max_key]  = [float("nan") if v is None else weight for v in pass_result]

    # Per-category scores
    for cat in rules_df["Main Category"].unique():
        cat_items = rules_df[rules_df["Main Category"] == cat]["Item"].tolist()
        pts_cols  = [f"{i} | pts" for i in cat_items]
        max_cols  = [f"{i} | max" for i in cat_items]
        earned    = results[pts_cols].sum(axis=1, min_count=1)
        max_pts   = results[max_cols].sum(axis=1, min_count=1)
        results[f"{cat} Score %"] = (earned / max_pts * 100).round(1)

    # Total score
    earned_total = results[item_pts_cols].sum(axis=1, min_count=1)
    max_total    = results[item_max_cols].sum(axis=1, min_count=1)
    results["Total Score %"] = (earned_total / max_total * 100).round(1)

    return results


# ── Session state ─────────────────────────────────────────────────────────────

if "sec_data" not in st.session_state:
    st.session_state.sec_data = DEFAULT_DATA


# ── Sidebar ───────────────────────────────────────────────────────────────────

st.sidebar.header("Data Management")

uploaded_rules = st.sidebar.file_uploader("Import Rules JSON", type=["json"])
if uploaded_rules:
    try:
        imported = json.load(uploaded_rules)
        if not isinstance(imported, list) or not all(
            all(k in row for k in ["Main Category", "Sub Security Score", "Item", "Value", "Weight"])
            for row in imported
        ):
            st.sidebar.error("Invalid format: expected a list of records with required fields.")
        else:
            for row in imported:
                row.setdefault("CSV Column", "")
                row.setdefault("Match Type", "boolean")
            st.session_state.sec_data = imported
            st.sidebar.success("Rules imported.")
    except Exception as e:
        st.sidebar.error(f"Import error: {e}")

if st.sidebar.button("Reset to Defaults"):
    st.session_state.sec_data = DEFAULT_DATA
    st.session_state.pop("domain_bytes", None)
    st.session_state.pop("domain_filename", None)
    st.rerun()


# ── Title ─────────────────────────────────────────────────────────────────────

st.title("🛡️ Security Scorecard Architect")
st.markdown("Define the scoring hierarchy, weights, and CSV mappings — then load a domain scan file to compute and export scores.")


# ── 1. Data Editor ────────────────────────────────────────────────────────────

st.subheader("1. Configure Hierarchy, Weights & Mappings")

df = pd.DataFrame(st.session_state.sec_data)
for col in REQUIRED_COLS:
    if col not in df.columns:
        df[col] = "" if col in ("CSV Column", "Match Type") else 0

column_config = {
    "Main Category":      st.column_config.TextColumn("Main Category",      help="Top-level grouping (DNS, Mail, Web…)"),
    "Sub Security Score": st.column_config.TextColumn("Sub Security Score", help="Grouping within a category"),
    "Item":               st.column_config.TextColumn("Item",               help="Specific security check name"),
    "Value":              st.column_config.TextColumn("Expected Value",      help="Target value matched against the CSV column"),
    "Weight":             st.column_config.NumberColumn("Weight", min_value=0, max_value=1000, step=1, help="Points awarded when this item passes"),
    "CSV Column":         st.column_config.TextColumn("CSV Column",         help="Exact column name in the domain scan CSV"),
    "Match Type":         st.column_config.SelectboxColumn(
                              "Match Type", options=MATCH_TYPES,
                              help="boolean=True/False · contains=substring · exact=full match · not_contains=absence · count_gte=token count ≥ N · bool_flag=numeric > 0"
                          ),
}

edited_df = st.data_editor(
    df[REQUIRED_COLS],
    num_rows="dynamic",
    use_container_width=True,
    column_config=column_config,
    key="data_editor_main",
)
st.session_state.sec_data = edited_df.to_dict(orient="records")


# ── 2. Sankey ─────────────────────────────────────────────────────────────────

st.subheader("2. Security Mindmap (Visual Flow)")


def plot_hierarchy(df):
    main_cats = df["Main Category"].unique().tolist()
    sub_ids   = (df["Main Category"] + " :: " + df["Sub Security Score"]).unique().tolist()
    item_ids  = (df["Main Category"] + " :: " + df["Sub Security Score"] + " :: " + df["Item"]).unique().tolist()

    all_node_ids = ["Total Score"] + main_cats + sub_ids + item_ids
    all_labels   = (
        ["Total Score"]
        + main_cats
        + [s.split(" :: ", 1)[1] for s in sub_ids]
        + [i.split(" :: ", 2)[2] for i in item_ids]
    )
    node_map = {nid: i for i, nid in enumerate(all_node_ids)}
    sources, targets, values = [], [], []

    for cat in main_cats:
        sources.append(node_map["Total Score"])
        targets.append(node_map[cat])
        values.append(int(df[df["Main Category"] == cat]["Weight"].sum()))

    for _, row in df.groupby(["Main Category", "Sub Security Score"])["Weight"].sum().reset_index().iterrows():
        sub_id = f"{row['Main Category']} :: {row['Sub Security Score']}"
        sources.append(node_map[row["Main Category"]])
        targets.append(node_map[sub_id])
        values.append(int(row["Weight"]))

    for _, row in df.iterrows():
        sub_id  = f"{row['Main Category']} :: {row['Sub Security Score']}"
        item_id = f"{row['Main Category']} :: {row['Sub Security Score']} :: {row['Item']}"
        sources.append(node_map[sub_id])
        targets.append(node_map[item_id])
        values.append(int(row["Weight"]))

    fig = go.Figure(data=[go.Sankey(
        node=dict(pad=20, thickness=20, line=dict(color="black", width=0.5), label=all_labels, color="deepskyblue"),
        link=dict(source=sources, target=targets, value=values, color="rgba(0, 191, 255, 0.2)"),
    )])
    fig.update_layout(title_text="Data Flow: Items → Sub-Scores → Categories → Total Score", font_size=12, height=600)
    st.plotly_chart(fig, use_container_width=True)


if not edited_df.empty:
    plot_hierarchy(edited_df)
else:
    st.warning("No data to visualize.")


# ── 3. Weight Distribution ────────────────────────────────────────────────────

st.subheader("3. Weight Distribution")

total_w = edited_df["Weight"].sum()
c1, c2, c3 = st.columns(3)
c1.metric("Total Weight Points", total_w)
c2.metric("Main Categories", len(edited_df["Main Category"].unique()))
c3.metric("Total Items (Tests)", len(edited_df))

if not edited_df.empty and total_w > 0:
    cat_summary = (
        edited_df.groupby("Main Category")["Weight"]
        .sum().reset_index().rename(columns={"Weight": "Total Pts"})
    )
    cat_summary["% of Total"] = (cat_summary["Total Pts"] / total_w * 100).round(1).astype(str) + "%"
    st.dataframe(cat_summary, use_container_width=True, hide_index=True)


# ── 4. Load Domain Scan Data ──────────────────────────────────────────────────

st.divider()
st.subheader("4. Load Domain Scan Data")

upload_col, info_col = st.columns([2, 3])

with upload_col:
    uploaded_data = st.file_uploader("Upload domain scan CSV", type=["csv"], key="data_uploader")
    if uploaded_data:
        new_bytes = uploaded_data.getvalue()
        if st.session_state.get("domain_filename") != uploaded_data.name or \
           st.session_state.get("domain_bytes") != new_bytes:
            st.session_state.domain_bytes    = new_bytes
            st.session_state.domain_filename = uploaded_data.name

with info_col:
    if "domain_bytes" in st.session_state:
        preview_df = load_csv(st.session_state.domain_bytes)
        st.info(
            f"**{st.session_state.domain_filename}**  \n"
            f"{len(preview_df):,} domains · {len(preview_df.columns)} columns"
        )
        st.caption("First 5 rows:")
        st.dataframe(preview_df.head(5), use_container_width=True, hide_index=True)

if "domain_bytes" in st.session_state:
    missing_cols = [
        r["CSV Column"] for _, r in edited_df.iterrows()
        if r.get("CSV Column") and r["CSV Column"] not in load_csv(st.session_state.domain_bytes).columns
    ]
    if missing_cols:
        st.warning(f"These CSV columns from your rules are not in the loaded file: `{'`, `'.join(set(missing_cols))}`")

    if st.button("▶ Run Scoring", type="primary", disabled=edited_df.empty):
        with st.spinner(f"Scoring {len(load_csv(st.session_state.domain_bytes)):,} domains against {len(edited_df)} rules…"):
            st.session_state.score_results = compute_scores(
                st.session_state.domain_bytes,
                json.dumps(edited_df.to_dict(orient="records")),
            )
        st.rerun()


# ── 5. Scoring Results ────────────────────────────────────────────────────────

if "score_results" in st.session_state:
    results_df  = st.session_state.score_results
    cat_score_cols = [c for c in results_df.columns if c.endswith("Score %") and c != "Total Score %"]
    all_score_cols = cat_score_cols + ["Total Score %"]

    st.divider()
    st.subheader("5. Scoring Results")

    scored     = results_df["Total Score %"].notna().sum()
    not_scored = results_df["Total Score %"].isna().sum()
    avg_total  = results_df["Total Score %"].mean()

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Domains Scored",    f"{scored:,}")
    m2.metric("Avg Total Score",   f"{avg_total:.1f}%" if pd.notna(avg_total) else "N/A")
    m3.metric("Unscored (no data)",f"{not_scored:,}")
    m4.metric("Rules Applied",     len(edited_df))

    tab_dist, tab_table, tab_items = st.tabs(["📊 Score Distribution", "📋 Domain Scores", "🔍 Item Pass Rates"])

    # ── Tab 1: Distribution ──
    with tab_dist:
        scored_only = results_df.dropna(subset=["Total Score %"])
        if not scored_only.empty:
            fig_hist = px.histogram(
                scored_only, x="Total Score %", nbins=20,
                title="Total Score Distribution",
                labels={"Total Score %": "Score (%)"},
                color_discrete_sequence=["deepskyblue"],
            )
            fig_hist.update_layout(bargap=0.05, xaxis_range=[0, 100], yaxis_title="Domains")
            st.plotly_chart(fig_hist, use_container_width=True)

            # Per-category averages
            if cat_score_cols:
                st.markdown("**Average score per category**")
                cat_cols = st.columns(len(cat_score_cols))
                for i, col_name in enumerate(cat_score_cols):
                    avg = results_df[col_name].mean()
                    cat_cols[i].metric(col_name, f"{avg:.1f}%" if pd.notna(avg) else "N/A")
        else:
            st.info("No domains could be scored with the current rules and data.")

    # ── Tab 2: Domain scores table ──
    with tab_table:
        display_cols = ["Domain", "Total Score %"] + cat_score_cols
        prog_config  = {
            c: st.column_config.ProgressColumn(c, min_value=0, max_value=100, format="%.1f%%")
            for c in all_score_cols
        }
        st.dataframe(
            results_df[display_cols].sort_values("Total Score %", ascending=False, na_position="last"),
            use_container_width=True,
            hide_index=True,
            column_config=prog_config,
        )

    # ── Tab 3: Item pass rates ──
    with tab_items:
        item_pass_cols = [c for c in results_df.columns if c.endswith("| pass")]
        if item_pass_cols:
            rows = []
            for ipc in item_pass_cols:
                item_name  = ipc.replace(" | pass", "")
                rule_row   = edited_df[edited_df["Item"] == item_name]
                category   = rule_row["Main Category"].values[0] if not rule_row.empty else "—"
                col_data   = results_df[ipc]
                evaluable  = int(col_data.notna().sum())
                passed     = int((col_data == True).sum())
                failed     = int((col_data == False).sum())
                na_count   = int(col_data.isna().sum())
                rows.append({
                    "Category":     category,
                    "Item":         item_name,
                    "Pass":         passed,
                    "Fail":         failed,
                    "N/A":          na_count,
                    "Pass Rate":    f"{passed / evaluable * 100:.1f}%" if evaluable > 0 else "N/A",
                })
            item_summary = pd.DataFrame(rows).sort_values(["Category", "Item"])
            st.dataframe(item_summary, use_container_width=True, hide_index=True)

    # ── Export ──
    st.divider()
    st.subheader("Export")

    summary_cols = ["Domain", "Total Score %"] + cat_score_cols
    ex1, ex2, ex3 = st.columns(3)

    with ex1:
        st.download_button(
            "📥 Summary CSV  (domain + scores)",
            data=results_df[summary_cols].to_csv(index=False),
            file_name="scorecard_results_summary.csv",
            mime="text/csv",
        )
    with ex2:
        st.download_button(
            "📥 Full CSV  (+ item pass/fail)",
            data=results_df.drop(columns=[c for c in results_df.columns if c.endswith("| pts") or c.endswith("| max")]).to_csv(index=False),
            file_name="scorecard_results_full.csv",
            mime="text/csv",
        )
    with ex3:
        st.download_button(
            "📥 Rules JSON",
            data=json.dumps(edited_df.to_dict(orient="records"), indent=2),
            file_name="hierarchical_security_scores.json",
            mime="application/json",
        )

else:
    # Rules export before any scoring run
    st.divider()
    col_json, col_csv = st.columns(2)
    with col_json:
        st.download_button(
            "📥 Export Rules as JSON",
            data=json.dumps(edited_df.to_dict(orient="records"), indent=2),
            file_name="hierarchical_security_scores.json",
            mime="application/json",
        )
    with col_csv:
        st.download_button(
            "📥 Export Rules as CSV",
            data=edited_df.to_csv(index=False),
            file_name="hierarchical_security_scores.csv",
            mime="text/csv",
        )
