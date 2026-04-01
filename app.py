import streamlit as st
import pandas as pd
import pickle
import json
import os
import plotly.figure_factory as ff
import plotly.express as px
import time
import urllib.parse

# ==========================================
# 1. PAGE CONFIGURATION & CYBER THEME
# ==========================================
st.set_page_config(
    page_title="SentinAI | Cyber Security Dashboard", 
    page_icon="🛡️", 
    layout="wide"
)

# Custom Hacker/Cyber Security Theme
st.markdown("""
    <style>
    .stApp { background-color: #0e1117; color: #00ff41; }
    h1, h2, h3 { color: #00ff41; }
    .stButton>button { background-color: #00ff41; color: #0e1117; font-weight: bold; border: none; width: 100%; }
    .stButton>button:hover { background-color: #00cc33; color: white; }
    .stDataFrame { border: 1px solid #00ff41; }
    .inference-card { padding: 20px; border: 1px solid #00ff41; border-radius: 10px; background-color: #161b22; margin-bottom: 20px; }
    </style>
""", unsafe_allow_html=True)

# ==========================================
# 2. LOAD ASSETS
# ==========================================
@st.cache_data
def load_data():
    # Load leaderboard and confusion matrix data
    df = pd.read_csv('models/model_leaderboard.csv')
    with open('models/confusion_matrices.json', 'r') as f:
        cms = json.load(f)
    return df, cms

@st.cache_resource
def load_assets():
    # Load the specialized TF-IDF vectorizer
    with open('models/tfidf_vectorizer.pkl', 'rb') as f:
        vectorizer = pickle.load(f)
    
    # Pre-load all 11 models for the Council
    all_models = {}
    model_files = sorted([f for f in os.listdir('models') if f.endswith('.pkl') and f != 'tfidf_vectorizer.pkl'])
    for f_name in model_files:
        display_name = f_name.replace(".pkl", "").replace("_", " ")
        with open(f"models/{f_name}", 'rb') as f:
            all_models[display_name] = pickle.load(f)
    return vectorizer, all_models

# Initialize global assets
try:
    leaderboard_df, confusion_matrices = load_data()
    vectorizer, all_models = load_assets()
except Exception as e:
    st.error(f"🚨 Initialization Error: {e}")
    st.stop()

# ==========================================
# 3. SIDEBAR NAVIGATION
# ==========================================
st.sidebar.title("🛡️ SentinAI Platform")
st.sidebar.markdown("**Project:** Enhancing Web Application Security")
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigation", ["🏆 Leaderboard", "📊 Model Profiles", "⚡ Live Inference Server"])

# ==========================================
# WINDOW 1: ALGORITHM LEADERBOARD (Index 1-11)
# ==========================================
if page == "🏆 Leaderboard":
    st.title("🛡️ Algorithm Leaderboard")
    st.markdown("Sort the arena results by your required metric to evaluate performance.")

    metrics = ["Accuracy (%)", "Precision (%)", "Recall (%)", "F1-Score (%)", "Time (sec)"]
    sort_metric = st.selectbox("Sort Rankings By:", metrics)
    sort_order = st.radio("Order:", ["Descending (Best First)", "Ascending"], horizontal=True)
    
    is_asc = True if sort_order == "Ascending" else False
    sorted_df = leaderboard_df.sort_values(by=sort_metric, ascending=is_asc).reset_index(drop=True)
    
    # Correcting Index to start at 1
    sorted_df.index = sorted_df.index + 1
    
    st.dataframe(
        sorted_df.style.highlight_max(subset=["Accuracy (%)", "Precision (%)", "F1-Score (%)"], color='#1e3d59')
                 .highlight_min(subset=["Time (sec)"], color='#1e3d59'),
        use_container_width=True, height=500
    )

# ==========================================
# WINDOW 2: MODEL PROFILES (Inference Explanation)
# ==========================================
elif page == "📊 Model Profiles":
    st.title("📊 Model Analytics & Global Inference")
    
    st.markdown("""
    ### 🧠 Project Inference Logic
    Inference is the real-time stage where the model transforms a raw HTTP string into a security classification based on learned patterns.
    """)
    
    

    col_inf1, col_inf2, col_inf3 = st.columns(3)
    with col_inf1:
        st.info("**1. Decoding**\nURLs are decoded and converted to lowercase.")
    with col_inf2:
        st.info("**2. TF-IDF Math**\nText is converted into a 5,000-feature mathematical vector.")
    with col_inf3:
        st.info("**3. Probability**\nModels calculate the statistical intent of the payload.")

    st.divider()
    
    model_choice = st.selectbox("Select Model to Inspect:", leaderboard_df['Model'].tolist())
    stats = leaderboard_df[leaderboard_df['Model'] == model_choice].iloc[0]
    
    col1, col2 = st.columns([1, 2])
    with col1:
        st.metric("F1-Score", f"{stats['F1-Score (%)']}%")
        st.metric("Avg. Latency", f"{stats['Time (sec)']}s")
        
    with col2:
        # Displaying individual confusion matrices
        cm = confusion_matrices[model_choice]
        z = [[cm[1][1], cm[1][0]], [cm[0][1], cm[0][0]]] 
        fig_cm = ff.create_annotated_heatmap(z, x=['Predicted Malicious', 'Predicted Safe'], y=['Actual Malicious', 'Actual Safe'], colorscale='Viridis')
        fig_cm.update_layout(plot_bgcolor='#0e1117', paper_bgcolor='#0e1117', font=dict(color='white'))
        st.plotly_chart(fig_cm, use_container_width=True)

# ==========================================
# WINDOW 3: LIVE INFERENCE SERVER (11 Votes)
# ==========================================
elif page == "⚡ Live Inference Server":
    st.title("⚡ Live Threat Detection Server")
    st.markdown("Perform simultaneous inference across the entire 11-Model Council.")
    
    user_input = st.text_area("Analyze Payload:", height=150, placeholder="e.g., ' OR 1=1 --")
    
    if st.button("🚨 EXECUTE COUNCIL VOTE"):
        if user_input.strip():
            # Real-time Inference logic
            clean_input = urllib.parse.unquote(user_input).lower()
            vec_input = vectorizer.transform([clean_input])
            
            st.subheader("🏛️ Individual Council Decisions (All 11 Votes)")
            votes_malicious = 0
            v_cols = st.columns(3)
            
            for i, (name, model) in enumerate(all_models.items()):
                pred = model.predict(vec_input)[0]
                with v_cols[i % 3]:
                    if pred == 1:
                        st.error(f"**{name}**\n🚨 MALICIOUS")
                        votes_malicious += 1
                    else:
                        st.success(f"**{name}**\n✅ SAFE")
            
            st.divider()
            if votes_malicious > 5:
                st.error(f"## 🛑 FINAL VERDICT: THREAT BLOCKED\n**Consensus: {votes_malicious}/11 models flagged this payload.**")
            else:
                st.success(f"## 🟢 FINAL VERDICT: TRAFFIC ALLOWED\n**Consensus: {11-votes_malicious}/11 models cleared this payload.**")
        else:
            st.warning("Enter a payload first.")