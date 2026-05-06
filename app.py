import io
import json

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="Security Scorecard Architect", layout="wide")

# Column order: reference → structure → description → scoring → mapping → metadata
REQUIRED_COLS = [
    "Control ID", "Main Category", "Sub Security Score", "Item",
    "Description", "Weight", "CSV Column", "Match Type", "Value",
    "Scoring Formula", "Requirement Level",
]
MATCH_TYPES        = ["boolean", "contains", "exact", "not_contains", "count_gte", "bool_flag"]
SCORING_FORMULAS   = ["binary (0/100)", "0/50/100", "0/25/75/100", "0/75/100", "tiered"]
REQUIREMENT_LEVELS = ["Required", "Recommended"]

# Strings that indicate the scanner had no result — not a domain failure
NA_SENTINELS = {"no answer", "timeout", "no existing query name", "nan", "none", ""}

# ── Default data — sourced from "Domain Security Scorecard – Selected Cases v02 (10 Apr 2026)" ──
DEFAULT_DATA = [
    # ── DOMAIN SECURITY · DNSSEC Score ───────────────────────────────────────────────────────────
    {
        "Control ID": "DE.21", "Main Category": "Domain Security", "Sub Security Score": "DNSSEC Score",
        "Item": "DS Record Existence",
        "Description": "Verifies domain has one or more valid DS records in the parent zone",
        "Weight": 94, "CSV Column": "dns_has_RRSIG", "Match Type": "boolean", "Value": "True",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "DE.22", "Main Category": "Domain Security", "Sub Security Score": "DNSSEC Score",
        "Item": "DNSKEY Record Existence",
        "Description": "Verifies domain has one or more valid DNSKEY records in the child zone",
        "Weight": 94, "CSV Column": "dns_has_RRSIG", "Match Type": "boolean", "Value": "True",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "DE.23", "Main Category": "Domain Security", "Sub Security Score": "DNSSEC Score",
        "Item": "DS DNSKEY Matching",
        "Description": "Verifies at least one DS record matches detected DNSKEY records and establishes secure delegation",
        "Weight": 94, "CSV Column": "dns_has_RRSIG", "Match Type": "boolean", "Value": "True",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    # ── MAIL SECURITY · DMARC Score ──────────────────────────────────────────────────────────────
    {
        "Control ID": "DE.25", "Main Category": "Mail Security", "Sub Security Score": "DMARC Score",
        "Item": "DMARC Record Existence",
        "Description": "Checks domain has a valid DMARC record starting with v=DMARC1, with correct k=v syntax and a valid p= value (none/quarantine/reject). Only one record permitted.",
        "Weight": 100, "CSV Column": "dns_has_dmarc", "Match Type": "boolean", "Value": "True",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "DE.26", "Main Category": "Mail Security", "Sub Security Score": "DMARC Score",
        "Item": "DMARC Policy",
        "Description": "Checks DMARC policy strictness. p=reject=100%, p=quarantine=75%, p=none=25%, absent=0%",
        "Weight": 100, "CSV Column": "dns_value_dmarc", "Match Type": "contains", "Value": "p=reject",
        "Scoring Formula": "0/25/75/100", "Requirement Level": "Required",
    },
    # ── MAIL SECURITY · DKIM Score ───────────────────────────────────────────────────────────────
    {
        "Control ID": "DE.24", "Main Category": "Mail Security", "Sub Security Score": "DKIM Score",
        "Item": "DKIM Record Existence",
        "Description": "Checks domain supports DKIM — name server answers NOERROR for _domainkey query and at least one valid DKIM key (v=DKIM1, k and p parameters) exists",
        "Weight": 100, "CSV Column": "dns_has_DKIM", "Match Type": "boolean", "Value": "True",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    # ── MAIL SECURITY · SPF Score ────────────────────────────────────────────────────────────────
    {
        "Control ID": "DE.27", "Main Category": "Mail Security", "Sub Security Score": "SPF Score",
        "Item": "SPF Record Existence",
        "Description": "Checks domain has exactly one TXT record starting with v=spf1 with valid syntax (resolve include/redirect, verify ≤10 DNS lookups)",
        "Weight": 100, "CSV Column": "dns_value_TXT", "Match Type": "contains", "Value": "v=spf1",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "DE.28", "Main Category": "Mail Security", "Sub Security Score": "SPF Score",
        "Item": "SPF Policy",
        "Description": "Checks SPF policy strictness. -all (fail)=100%, ~all (softfail)=75%, +all/?all=0%",
        "Weight": 100, "CSV Column": "dns_value_TXT", "Match Type": "contains", "Value": "-all",
        "Scoring Formula": "0/75/100", "Requirement Level": "Required",
    },
    # ── MAIL SECURITY · Advanced Mail Security ───────────────────────────────────────────────────
    {
        "Control ID": "ES.6", "Main Category": "Mail Security", "Sub Security Score": "Advanced Mail Security",
        "Item": "MTA-STS Policy Mode",
        "Description": "Checks MTA-STS DNS record and policy.txt file. enforce=100% (full TLS enforcement), testing=50% (monitoring only), absent=0%",
        "Weight": 80, "CSV Column": "", "Match Type": "boolean", "Value": "",
        "Scoring Formula": "0/50/100", "Requirement Level": "Recommended",
    },
    {
        "Control ID": "ES.7", "Main Category": "Mail Security", "Sub Security Score": "Advanced Mail Security",
        "Item": "TLS Reporting (TLS-RPT)",
        "Description": "Checks for _smtp._tls DNS record with valid mailto address. present=100% (reporting enabled), absent=0% (no visibility)",
        "Weight": 80, "CSV Column": "", "Match Type": "boolean", "Value": "",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Recommended",
    },
    {
        "Control ID": "ES.8", "Main Category": "Mail Security", "Sub Security Score": "Advanced Mail Security",
        "Item": "Verified Logo in Emails (BIMI)",
        "Description": "Checks BIMI DNS record and VMC certificate. BIMI+VMC=100% (verified brand identity), BIMI only=50% (logo shown), absent=0%",
        "Weight": 80, "CSV Column": "", "Match Type": "boolean", "Value": "",
        "Scoring Formula": "0/50/100", "Requirement Level": "Recommended",
    },
    # ── MAIL SECURITY · TLS Security (Mail) ──────────────────────────────────────────────────────
    {
        "Control ID": "T.4.1", "Main Category": "Mail Security", "Sub Security Score": "TLS Security (Mail)",
        "Item": "STARTTLS Available",
        "Description": "Checks if receiving MX servers support STARTTLS encryption. Prerequisite for all mail TLS sub-tests.",
        "Weight": 94, "CSV Column": "ssl_enabled", "Match Type": "boolean", "Value": "True",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "T.4.2", "Main Category": "Mail Security", "Sub Security Score": "TLS Security (Mail)",
        "Item": "TLS Version (Mail)",
        "Description": "Checks mail servers support secure TLS only. TLS 1.3=Good, TLS 1.2=Sufficient, TLS 1.1/1.0=Phase-out, SSL 3.0/2.0/1.0=Insufficient",
        "Weight": 94, "CSV Column": "fx_hcj__secu_tls", "Match Type": "bool_flag", "Value": "True",
        "Scoring Formula": "tiered", "Requirement Level": "Required",
    },
    {
        "Control ID": "T.4.7", "Main Category": "Mail Security", "Sub Security Score": "TLS Security (Mail)",
        "Item": "TLS Compression Disabled",
        "Description": "Checks TLS compression is disabled on MX servers (prevents CRIME attacks). Good=No compression, Sufficient=App-level only, Insufficient=TLS compression",
        "Weight": 94, "CSV Column": "", "Match Type": "boolean", "Value": "",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "T.4.8", "Main Category": "Mail Security", "Sub Security Score": "TLS Security (Mail)",
        "Item": "Secure Renegotiation",
        "Description": "Checks insecure TLS renegotiation is disabled on MX servers. Good=Off (or N/A for TLS 1.3), Insufficient=On",
        "Weight": 94, "CSV Column": "", "Match Type": "boolean", "Value": "",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "T.5.3", "Main Category": "Mail Security", "Sub Security Score": "TLS Security (Mail)",
        "Item": "Certificate Signature (Mail)",
        "Description": "Checks MX server certificate is signed with secure hash algorithm. Good=SHA-256/384/512, Insufficient=SHA-1/MD5",
        "Weight": 94, "CSV Column": "", "Match Type": "boolean", "Value": "",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "T.6.1", "Main Category": "Mail Security", "Sub Security Score": "TLS Security (Mail)",
        "Item": "DANE TLSA Existence",
        "Description": "Checks MX server name servers provide TLSA records for DANE. Requires DNSSEC. Fails if PKIX-TA(0) or PKIX-EE(1) types used.",
        "Weight": 94, "CSV Column": "", "Match Type": "boolean", "Value": "",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Recommended",
    },
    # ── MAIL SECURITY · DNSSEC Score (Mail) ──────────────────────────────────────────────────────
    {
        "Control ID": "T.2.3", "Main Category": "Mail Security", "Sub Security Score": "DNSSEC Score (Mail)",
        "Item": "Mail Server DNSSEC Existence",
        "Description": "Checks if mail server domain SOA record is DNSSEC signed (DS + DNSKEY records present)",
        "Weight": 86, "CSV Column": "", "Match Type": "boolean", "Value": "",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "T.2.4", "Main Category": "Mail Security", "Sub Security Score": "DNSSEC Score (Mail)",
        "Item": "Mail Server DNSSEC Validity",
        "Description": "Verifies mail server domain has a valid DNSSEC signature (DS record matches DNSKEY, secure delegation established)",
        "Weight": 86, "CSV Column": "", "Match Type": "boolean", "Value": "",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    # ── WEB SECURITY · HTTPS/TLS Security ────────────────────────────────────────────────────────
    {
        "Control ID": "W.3.1", "Main Category": "Web Security", "Sub Security Score": "HTTPS/TLS Security",
        "Item": "HTTPS Availability",
        "Description": "Checks if web server is reachable over HTTPS",
        "Weight": 100, "CSV Column": "ssl_enabled", "Match Type": "boolean", "Value": "True",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "W.3.2", "Main Category": "Web Security", "Sub Security Score": "HTTPS/TLS Security",
        "Item": "HTTPS Redirect",
        "Description": "Checks if HTTP traffic is redirected to HTTPS",
        "Weight": 100, "CSV Column": "URL_history", "Match Type": "contains", "Value": "https://",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "W.3.4", "Main Category": "Web Security", "Sub Security Score": "HTTPS/TLS Security",
        "Item": "HSTS Header",
        "Description": "Checks if HTTP Strict Transport Security (HSTS) header is present",
        "Weight": 100, "CSV Column": "", "Match Type": "boolean", "Value": "",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "W.4.1", "Main Category": "Web Security", "Sub Security Score": "HTTPS/TLS Security",
        "Item": "TLS Version (Web)",
        "Description": "Checks web server supports only secure TLS versions. TLS 1.3=Good, TLS 1.2=Sufficient, TLS 1.1/1.0=Phase-out, SSL=Insufficient",
        "Weight": 100, "CSV Column": "fx_hcj__secu_tls", "Match Type": "bool_flag", "Value": "True",
        "Scoring Formula": "tiered", "Requirement Level": "Required",
    },
    # ── WEB SECURITY · Security Headers ──────────────────────────────────────────────────────────
    {
        "Control ID": "W.6.2", "Main Category": "Web Security", "Sub Security Score": "Security Headers",
        "Item": "X-Content-Type-Options Header",
        "Description": "Checks for X-Content-Type-Options header to prevent MIME-type sniffing attacks",
        "Weight": 100, "CSV Column": "fx_hcj__secu_xss", "Match Type": "bool_flag", "Value": "True",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "W.6.3", "Main Category": "Web Security", "Sub Security Score": "Security Headers",
        "Item": "Content-Security-Policy Header",
        "Description": "Checks if Content-Security-Policy (CSP) header is present to mitigate XSS and injection attacks",
        "Weight": 100, "CSV Column": "fx_hcj__secu_contentPolicy", "Match Type": "bool_flag", "Value": "True",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Required",
    },
    {
        "Control ID": "W.6.4", "Main Category": "Web Security", "Sub Security Score": "Security Headers",
        "Item": "Referrer-Policy Header",
        "Description": "Checks if Referrer-Policy header is present to control referrer information leakage",
        "Weight": 100, "CSV Column": "", "Match Type": "boolean", "Value": "",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Recommended",
    },
    # ── WEB SECURITY · Security Contact ──────────────────────────────────────────────────────────
    {
        "Control ID": "ES.11", "Main Category": "Web Security", "Sub Security Score": "Security Contact",
        "Item": "Security Contact File (security.txt)",
        "Description": "Checks for syntactically valid security.txt at /.well-known/security.txt. Full disclosure=100%, limited info=50%, absent=0%",
        "Weight": 80, "CSV Column": "", "Match Type": "boolean", "Value": "",
        "Scoring Formula": "0/50/100", "Requirement Level": "Recommended",
    },
    # ── WEB SECURITY · CAA Records ───────────────────────────────────────────────────────────────
    {
        "Control ID": "W.CAA", "Main Category": "Web Security", "Sub Security Score": "CAA Records",
        "Item": "CAA Record Existence",
        "Description": "Checks if domain has CAA records to restrict which Certificate Authorities may issue TLS certificates",
        "Weight": 100, "CSV Column": "dns_has_CAA", "Match Type": "boolean", "Value": "True",
        "Scoring Formula": "binary (0/100)", "Requirement Level": "Recommended",
    },
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

    # Per-sub-score scores
    for (cat, sub), grp in rules_df.groupby(["Main Category", "Sub Security Score"], sort=False):
        sub_items = grp["Item"].tolist()
        pts_cols  = [f"{i} | pts" for i in sub_items]
        max_cols  = [f"{i} | max" for i in sub_items]
        earned    = results[pts_cols].sum(axis=1, min_count=1)
        max_pts   = results[max_cols].sum(axis=1, min_count=1)
        results[f"{cat} / {sub} Score %"] = (earned / max_pts * 100).round(1)

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
                row.setdefault("Control ID", "")
                row.setdefault("Description", "")
                row.setdefault("CSV Column", "")
                row.setdefault("Match Type", "boolean")
                row.setdefault("Scoring Formula", "binary (0/100)")
                row.setdefault("Requirement Level", "Required")
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
    "Control ID":         st.column_config.TextColumn("Control ID",          help="Reference ID from the scorecard spec (e.g. DE.25, ES.6, W.3.1)"),
    "Main Category":      st.column_config.TextColumn("Main Category",       help="Top-level grouping (DNS, Mail, Web…)"),
    "Sub Security Score": st.column_config.TextColumn("Sub Security Score",  help="Grouping within a category"),
    "Item":               st.column_config.TextColumn("Item",                help="Specific security check name"),
    "Description":        st.column_config.TextColumn("Description",         help="What this test checks and how it is evaluated"),
    "Weight":             st.column_config.NumberColumn("Weight", min_value=0, max_value=1000, step=1, help="Points awarded when this item passes"),
    "CSV Column":         st.column_config.TextColumn("CSV Column",          help="Exact column name in the domain scan CSV"),
    "Match Type":         st.column_config.SelectboxColumn(
                              "Match Type", options=MATCH_TYPES,
                              help="boolean=True/False · contains=substring · exact=full match · not_contains=absence · count_gte=token count ≥ N · bool_flag=numeric > 0"
                          ),
    "Value":              st.column_config.TextColumn("Expected Value",       help="Target value matched against the CSV column"),
    "Scoring Formula":    st.column_config.SelectboxColumn(
                              "Scoring Formula", options=SCORING_FORMULAS,
                              help="binary=0/100 · 0/50/100 · 0/25/75/100 · 0/75/100 · tiered (multi-level)"
                          ),
    "Requirement Level":  st.column_config.SelectboxColumn(
                              "Requirement Level", options=REQUIREMENT_LEVELS,
                              help="Required=mandatory baseline · Recommended=best practice"
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


def plot_hierarchy(df, hide_total=False):
    main_cats = df["Main Category"].unique().tolist()
    sub_ids   = (df["Main Category"] + " :: " + df["Sub Security Score"]).unique().tolist()
    item_ids  = (df["Main Category"] + " :: " + df["Sub Security Score"] + " :: " + df["Item"]).unique().tolist()

    if hide_total:
        all_node_ids = main_cats + sub_ids + item_ids
        all_labels   = (
            main_cats
            + [s.split(" :: ", 1)[1] for s in sub_ids]
            + [i.split(" :: ", 2)[2] for i in item_ids]
        )
    else:
        all_node_ids = ["Total Score"] + main_cats + sub_ids + item_ids
        all_labels   = (
            ["Total Score"]
            + main_cats
            + [s.split(" :: ", 1)[1] for s in sub_ids]
            + [i.split(" :: ", 2)[2] for i in item_ids]
        )
    node_map = {nid: i for i, nid in enumerate(all_node_ids)}
    sources, targets, values = [], [], []

    if not hide_total:
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

    title = "Data Flow: Items → Sub-Scores → Categories" + ("" if hide_total else " → Total Score")
    fig = go.Figure(data=[go.Sankey(
        node=dict(pad=20, thickness=20, line=dict(color="black", width=0.5), label=all_labels, color="deepskyblue"),
        link=dict(source=sources, target=targets, value=values, color="rgba(0, 191, 255, 0.2)"),
    )])
    fig.update_layout(
        title_text=title,
        font_size=12,
        height=600,
        dragmode="pan",
    )
    st.plotly_chart(
        fig,
        use_container_width=True,
        config={
            "scrollZoom": True,
            "displayModeBar": True,
            "modeBarButtonsToAdd": ["zoom2d", "pan2d", "resetScale2d"],
            "modeBarButtonsToRemove": ["lasso2d", "select2d"],
            "displaylogo": False,
        },
    )


if not edited_df.empty:
    vis_ctrl_col, vis_toggle_col = st.columns([5, 2])
    with vis_toggle_col:
        hide_total_node = st.checkbox("Hide Total Score node", value=False, key="hide_total_node")
    plot_hierarchy(edited_df, hide_total=hide_total_node)
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
    results_df     = st.session_state.score_results
    sub_score_cols = [c for c in results_df.columns if c.endswith("Score %") and " / " in c]
    cat_score_cols = [c for c in results_df.columns if c.endswith("Score %") and c != "Total Score %" and " / " not in c]
    all_score_cols = sub_score_cols + cat_score_cols + ["Total Score %"]

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
            # Bar chart: average score per sub-score
            sub_bar_rows = []
            for col_name in sub_score_cols:
                cat, sub = col_name.replace(" Score %", "").split(" / ", 1)
                avg = results_df[col_name].mean()
                if pd.notna(avg):
                    sub_bar_rows.append({"Sub Score": sub, "Category": cat, "Avg Score %": round(avg, 1)})
            if sub_bar_rows:
                sub_bar_df = pd.DataFrame(sub_bar_rows)
                fig_bar = px.bar(
                    sub_bar_df, x="Sub Score", y="Avg Score %", color="Category",
                    title="Average Score per Sub-Score",
                    text="Avg Score %",
                    labels={"Avg Score %": "Avg Score (%)", "Sub Score": ""},
                    color_discrete_sequence=px.colors.qualitative.Set2,
                )
                fig_bar.update_traces(texttemplate="%{text:.1f}%", textposition="outside")
                fig_bar.update_layout(
                    yaxis=dict(range=[0, 110], title="Avg Score (%)"),
                    xaxis=dict(tickangle=-30),
                    bargap=0.25,
                    legend_title_text="Category",
                )
                st.plotly_chart(fig_bar, use_container_width=True)

            # Score-band summary table
            bands = [
                (0,  20,  "0 – 20",  "Critical"),
                (20, 40,  "20 – 40", "Poor"),
                (40, 60,  "40 – 60", "Fair"),
                (60, 80,  "60 – 80", "Good"),
                (80, 100, "80 – 100","Excellent"),
            ]
            total_scored = len(scored_only)
            band_rows = []
            for lo, hi, range_label, rating in bands:
                mask  = (scored_only["Total Score %"] >= lo) & (scored_only["Total Score %"] < hi)
                count = int(mask.sum())
                # include upper boundary in last band
                if hi == 100:
                    mask  = (scored_only["Total Score %"] >= lo) & (scored_only["Total Score %"] <= hi)
                    count = int(mask.sum())
                pct   = f"{count / total_scored * 100:.1f}%" if total_scored > 0 else "—"
                avg   = scored_only.loc[mask, "Total Score %"].mean()
                band_rows.append({
                    "Score Range": range_label,
                    "Rating":      rating,
                    "Domains":     count,
                    "% of Total":  pct,
                    "Avg Score":   f"{avg:.1f}%" if count > 0 else "—",
                })
            st.dataframe(pd.DataFrame(band_rows), use_container_width=True, hide_index=True)

            # Per-category averages
            if cat_score_cols:
                st.markdown("**Average score per main category**")
                cat_cols_ui = st.columns(len(cat_score_cols))
                for i, col_name in enumerate(cat_score_cols):
                    avg = results_df[col_name].mean()
                    cat_cols_ui[i].metric(col_name, f"{avg:.1f}%" if pd.notna(avg) else "N/A")

            # Per-sub-score averages grouped by category
            if sub_score_cols:
                st.markdown("**Average score per sub-score**")
                cats_for_subs = edited_df["Main Category"].unique().tolist()
                for cat in cats_for_subs:
                    subs_for_cat = [c for c in sub_score_cols if c.startswith(f"{cat} / ")]
                    if not subs_for_cat:
                        continue
                    st.caption(cat)
                    sub_ui = st.columns(len(subs_for_cat))
                    for i, col_name in enumerate(subs_for_cat):
                        label = col_name.split(" / ", 1)[1]  # strip "Category / " prefix
                        avg   = results_df[col_name].mean()
                        sub_ui[i].metric(label, f"{avg:.1f}%" if pd.notna(avg) else "N/A")
        else:
            st.info("No domains could be scored with the current rules and data.")

    # ── Tab 2: Domain scores table ──
    with tab_table:
        display_cols      = ["Domain", "Total Score %"] + cat_score_cols + sub_score_cols
        score_disp_cols   = [c for c in display_cols if c != "Domain"]
        # strip "Category / " prefix from sub-score column names for display
        rename_map        = {c: c.split(" / ", 1)[1].replace(" Score %", "") for c in sub_score_cols}
        display_df        = (
            results_df[display_cols]
            .sort_values("Total Score %", ascending=False, na_position="last")
            .rename(columns=rename_map)
        )
        renamed_score_cols = [rename_map.get(c, c) for c in score_disp_cols]

        def _traffic_light(val):
            if pd.isna(val):
                return ""
            if val >= 80:
                return "background-color: #2d7d46; color: white"   # green
            elif val >= 60:
                return "background-color: #c6a800; color: black"   # yellow
            elif val >= 40:
                return "background-color: #c96a00; color: white"   # orange
            else:
                return "background-color: #c0392b; color: white"   # red

        pd.set_option("styler.render.max_elements", display_df.size)
        styled = (
            display_df.style
            .map(_traffic_light, subset=renamed_score_cols)
            .format(lambda v: f"{v:.1f}%" if pd.notna(v) else "N/A", subset=renamed_score_cols)
        )
        st.dataframe(styled, use_container_width=True, hide_index=True)

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

    summary_cols = ["Domain", "Total Score %"] + cat_score_cols + sub_score_cols
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
