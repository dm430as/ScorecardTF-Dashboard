import streamlit as st
import pandas as pd
import json
import plotly.graph_objects as go

st.set_page_config(page_title="Hierarchical Security Architect", layout="wide")

# --- Default Data Structure (4-Level Hierarchy) ---
if 'sec_data' not in st.session_state:
    st.session_state.sec_data = [
        {"Main Category": "DNS", "Sub Security Score": "DNSSEC Integrity", "Item": "Algorithm Type", "Value": "ECDSA P-256", "Weight": 25},
        {"Main Category": "DNS", "Sub Security Score": "DNSSEC Integrity", "Item": "RRSIG Validity", "Value": "Valid", "Weight": 25},
        {"Main Category": "DNS", "Sub Security Score": "Redundancy", "Item": "NS Count", "Value": "3", "Weight": 50},
        {"Main Category": "Mail", "Sub Security Score": "Authentication", "Item": "SPF Policy", "Value": "-all", "Weight": 30},
        {"Main Category": "Mail", "Sub Security Score": "Authentication", "Item": "DMARC Policy", "Value": "reject", "Weight": 40},
        {"Main Category": "Mail", "Sub Security Score": "Encryption", "Item": "DANE TLSA", "Value": "Present", "Weight": 30},
        {"Main Category": "Web", "Sub Security Score": "TLS Config", "Item": "Protocol Version", "Value": "TLS 1.3", "Weight": 60},
        {"Main Category": "Web", "Sub Security Score": "TLS Config", "Item": "Cipher Suite", "Value": "Strong", "Weight": 40},
    ]

st.title("🛡️ Hierarchical Security Score Architect")
st.markdown("Map **Items** to **Sub-Scores**, **Main Categories**, and finally the **Total Score**.")

# --- Sidebar: Import/Export ---
st.sidebar.header("Data Management")
uploaded_file = st.sidebar.file_uploader("Import JSON", type=["json"])
if uploaded_file:
    st.session_state.sec_data = json.load(uploaded_file)

# --- 1. Data Editor ---
st.subheader("1. Configure Hierarchy & Weights")
df = pd.DataFrame(st.session_state.sec_data)
edited_df = st.data_editor(df, num_rows="dynamic", use_container_width=True)

# --- 2. Hierarchical Mindmap (Sankey) ---
st.subheader("2. Security Mindmap (Visual Flow)")

def plot_hierarchy(df):
    # Unique Nodes
    main_cats = df["Main Category"].unique().tolist()
    sub_scores = df["Sub Security Score"].unique().tolist()
    items = df["Item"].unique().tolist()
    all_nodes = ["Total Score"] + main_cats + sub_scores + items
    
    node_map = {name: i for i, name in enumerate(all_nodes)}
    
    sources, targets, values = [], [], []
    
    # Tier 1 -> Tier 2 (Total -> Main Category)
    for cat in main_cats:
        sources.append(node_map["Total Score"])
        targets.append(node_map[cat])
        values.append(df[df["Main Category"] == cat]["Weight"].sum())
        
    # Tier 2 -> Tier 3 (Main Category -> Sub Security Score)
    sub_cat_pairs = df[["Main Category", "Sub Security Score", "Weight"]].groupby(["Main Category", "Sub Security Score"]).sum().reset_index()
    for _, row in sub_cat_pairs.iterrows():
        sources.append(node_map[row["Main Category"]])
        targets.append(node_map[row["Sub Security Score"]])
        values.append(row["Weight"])
        
    # Tier 3 -> Tier 4 (Sub Security Score -> Item)
    for _, row in df.iterrows():
        sources.append(node_map[row["Sub Security Score"]])
        targets.append(node_map[row["Item"]])
        values.append(row["Weight"])

    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad=20, thickness=20, 
            line=dict(color="black", width=0.5), 
            label=all_nodes,
            color="deepskyblue"
        ),
        link=dict(source=sources, target=targets, value=values, color="rgba(0, 191, 255, 0.2)")
    )])
    
    fig.update_layout(title_text="Data Flow: Items ➔ Sub-Scores ➔ Categories ➔ Total", font_size=12, height=600)
    st.plotly_chart(fig, use_container_width=True)

plot_hierarchy(edited_df)

# --- 3. Summary View ---
st.subheader("3. Aggregated View")
col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Total Weight Pts", f"{edited_df['Weight'].sum()}")
with col2:
    st.metric("Main Categories", len(edited_df['Main Category'].unique()))
with col3:
    st.metric("Total Items (Tests)", len(edited_df))

# --- 4. Export ---
st.divider()
json_str = edited_df.to_json(orient="records")
st.download_button(
    label="📥 Export Hierarchical Data (JSON)",
    data=json_str,
    file_name="hierarchical_security_scores.json",
    mime="application/json",
)
