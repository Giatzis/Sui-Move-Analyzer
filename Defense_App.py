"""
Streamlit Defense App for Comprehensive Sui Analyzer v1.0

✅ UPDATED FOR v1.0: Privilege Classification Fix
✅ NEW FEATURE: Vulnerability breakdown by category (AUTH, TIME, RES, CONS)
✅ NEW FEATURE: Interactive D3.js DCR Graph Visualization embedded
✅ COMPATIBLE: Works with Comprehensive_Sui_Analyzer.py
✅ HOTFIX: Cleaned UI, delegating graph styling strictly to backend

Author: PhD Candidate Giatzis Antonios
Institution: University of Macedonia, Greece
Date: February 8, 2026
"""

import streamlit as st
import streamlit.components.v1 as components
import sys
import os
from io import StringIO
import json
import time

# ============================================================================
# IMPORT ANALYZER
# ============================================================================
try:
    from Comprehensive_Sui_Analyzer import ComprehensiveSuiAnalyzer, PatternTypes
except ImportError:
    st.error("⚠️ CRITICAL: `Comprehensive_Sui_Analyzer.py` not found. Please ensure the file is in the same directory.")
    st.stop()

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================
st.set_page_config(
    page_title="Sui Move Analyzer - PhD Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# PROFESSIONAL LIGHT COLOR THEME (FORCED)
# ============================================================================
st.markdown("""
<style>
    /* ===== GLOBAL STYLES & FORCE LIGHT THEME ===== */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    .stApp {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Force Light background on main container */
    [data-testid="stAppViewContainer"] {
        background-color: #f8fafc !important;
    }
    
    /* Force Light background on header */
    [data-testid="stHeader"] {
        background-color: #f8fafc !important;
    }
    
    /* Force Light background on sidebar */
    [data-testid="stSidebar"] {
        background-color: #ffffff !important;
        border-right: 1px solid #e2e8f0;
    }
    
    /* Force Dark text everywhere to override system dark mode */
    .stApp, .stApp p, .stApp span, .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6, .stApp label, .stApp li {
        color: #1e293b !important;
    }
    
    /* ===== HEADER STYLES ===== */
    .hero-container {
        background: linear-gradient(145deg, #ffffff 0%, #f1f5f9 100%);
        padding: 2.5rem 2rem;
        border-radius: 12px;
        margin-bottom: 2rem;
        border: 1px solid #e2e8f0;
        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
    }
    
    .hero-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #0f172a !important;
        margin: 0 0 0.5rem 0;
        letter-spacing: -0.02em;
    }
    
    .hero-subtitle {
        font-size: 1rem;
        color: #475569 !important;
        margin: 0;
        font-weight: 400;
    }
    
    .hero-badge {
        display: inline-block;
        background: #0f766e;
        color: white !important;
        padding: 0.35rem 0.9rem;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 500;
        margin-top: 1rem;
        letter-spacing: 0.02em;
    }
    
    .institution-badge {
        background: #ffffff;
        padding: 1rem 1.5rem;
        border-radius: 10px;
        border: 1px solid #cbd5e1;
        text-align: center;
        box-shadow: 0 1px 2px rgba(0,0,0,0.03);
    }
    
    .institution-name {
        color: #1e293b !important;
        font-size: 0.95rem;
        font-weight: 600;
        margin: 0;
    }
    
    .institution-type {
        color: #64748b !important;
        font-size: 0.8rem;
        margin: 0.3rem 0 0 0;
    }
    
    /* ===== METRIC CARDS ===== */
    .metric-card {
        background: #ffffff;
        padding: 1.5rem;
        border-radius: 10px;
        text-align: center;
        border: 1px solid #e2e8f0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.04);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 12px rgba(0,0,0,0.08);
    }
    
    .metric-card.patterns { border-left: 4px solid #0d9488; }
    .metric-card.vulnerabilities { border-left: 4px solid #dc2626; }
    .metric-card.dcr { border-left: 4px solid #6366f1; }
    .metric-card.fixes { border-left: 4px solid #8b5cf6; }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        margin: 0;
        color: #0f172a !important;
    }
    
    .metric-label {
        font-size: 0.85rem;
        font-weight: 600;
        margin: 0.4rem 0 0 0;
        color: #475569 !important;
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }
    
    /* ===== CATEGORY BADGES ===== */
    .category-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 1.25rem;
        text-align: center;
        box-shadow: 0 1px 3px rgba(0,0,0,0.02);
    }
    
    .category-badge {
        display: inline-block;
        padding: 0.4rem 1rem;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.9rem;
        margin: 0;
    }
    
    .badge-auth { background: #fef2f2; color: #b91c1c !important; border: 1px solid #fecaca; }
    .badge-time { background: #fffbeb; color: #b45309 !important; border: 1px solid #fde68a; }
    .badge-res { background: #eff6ff; color: #1d4ed8 !important; border: 1px solid #bfdbfe; }
    .badge-cons { background: #faf5ff; color: #7c3aed !important; border: 1px solid #ddd6fe; }
    
    .category-description {
        font-size: 0.8rem;
        color: #64748b !important;
        margin-top: 0.6rem;
    }
    
    /* ===== DETECTION METHOD CARDS ===== */
    .method-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 1.25rem;
        text-align: center;
        box-shadow: 0 1px 3px rgba(0,0,0,0.02);
    }
    
    .method-count {
        font-size: 2rem;
        font-weight: 700;
        margin: 0;
        color: #0f172a !important;
    }
    
    .method-name {
        font-size: 0.9rem;
        font-weight: 600;
        color: #334155 !important;
        margin: 0.4rem 0 0.2rem 0;
    }
    
    .method-description {
        font-size: 0.75rem;
        color: #64748b !important;
        margin: 0;
    }
    
    /* ===== SECTION HEADERS ===== */
    .section-header {
        display: flex;
        align-items: center;
        gap: 0.6rem;
        margin: 1.8rem 0 1.2rem 0;
        padding-bottom: 0.8rem;
        border-bottom: 1px solid #cbd5e1;
    }
    
    .section-title {
        font-size: 1.15rem;
        font-weight: 600;
        color: #0f172a !important;
        margin: 0;
    }
    
    /* ===== ANALYZE BUTTON ===== */
    .stButton > button {
        background: #0f766e !important;
        color: white !important;
        font-weight: 600 !important;
        padding: 0.7rem 2rem !important;
        border-radius: 8px !important;
        border: none !important;
        box-shadow: 0 4px 6px rgba(15, 118, 110, 0.2) !important;
    }
    
    /* ===== PROGRESS BAR ===== */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, #0f766e 0%, #14b8a6 100%);
    }
    
    /* ===== FOOTER ===== */
    .footer-container {
        background: #ffffff;
        padding: 1.5rem 2rem;
        border-radius: 10px;
        margin-top: 2.5rem;
        text-align: center;
        border: 1px solid #e2e8f0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.02);
    }
    
    .footer-title {
        color: #1e293b !important;
        font-size: 1rem;
        font-weight: 600;
        margin: 0 0 0.3rem 0;
    }
    
    .footer-institution {
        color: #64748b !important;
        font-size: 0.9rem;
        margin: 0 0 0.8rem 0;
    }
    
    .feature-pill {
        display: inline-block;
        background: #f1f5f9;
        color: #334155 !important;
        padding: 0.25rem 0.7rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 500;
        margin: 0.15rem;
        border: 1px solid #cbd5e1;
    }
    
    /* ===== TAB STYLING ===== */
    .stTabs [data-baseweb="tab-list"] {
        background: #e2e8f0;
        padding: 4px;
        border-radius: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        color: #475569 !important;
        font-weight: 500;
    }
    
    .stTabs [aria-selected="true"] {
        background: #ffffff !important;
        color: #0f766e !important;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    /* ===== EXPANDER STYLING ===== */
    .streamlit-expanderHeader {
        background: #f8fafc;
        border-radius: 6px;
        border: 1px solid #e2e8f0;
        color: #1e293b !important;
        font-weight: 600;
    }
    
    /* ===== ONTOLOGY REASONING TAB ===== */
    .reasoning-header {
        background: linear-gradient(145deg, #eff6ff 0%, #e0e7ff 100%);
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid #c7d2fe;
        margin-bottom: 1.25rem;
    }

    .reasoning-title {
        font-size: 1.1rem;
        font-weight: 700;
        color: #1e40af !important;
        margin: 0 0 0.3rem 0;
    }

    .reasoning-subtitle {
        font-size: 0.85rem;
        color: #4f46e5 !important;
        margin: 0;
    }

    .sparql-finding {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 1.25rem;
        margin-bottom: 0.75rem;
        border-left: 4px solid #6366f1;
        box-shadow: 0 2px 4px rgba(0,0,0,0.03);
    }

    .sparql-finding-title {
        font-size: 0.95rem;
        font-weight: 700;
        color: #0f172a !important;
        margin: 0 0 0.4rem 0;
    }

    .sparql-evidence {
        font-size: 0.82rem;
        color: #475569 !important;
        background: #f8fafc;
        padding: 0.6rem 0.8rem;
        border-radius: 6px;
        margin-top: 0.5rem;
        font-family: 'SF Mono', 'Fira Code', monospace;
        border: 1px solid #e2e8f0;
    }

    .sparql-empty {
        background: #f0fdf4;
        color: #166534 !important;
        padding: 1.2rem;
        border-radius: 10px;
        text-align: center;
        font-weight: 600;
        border: 1px solid #bbf7d0;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# SIDEBAR - Configuration
# ============================================================================
with st.sidebar:
    st.markdown("""
    <div style="background: #ffffff; padding: 1.25rem; border-radius: 10px; margin-bottom: 1.25rem; text-align: center; border: 1px solid #e2e8f0; box-shadow: 0 2px 4px rgba(0,0,0,0.02);">
        <p style="color: #0f172a; font-size: 1.1rem; font-weight: 700; margin: 0 0 0.2rem 0;">🎓 PhD Defense Tool</p>
        <p style="color: #64748b; font-size: 0.85rem; margin: 0;">Sui Move Security Analyzer</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown('<span style="background:#0f766e;color:white;padding:0.3em 0.8em;border-radius:5px;font-size:0.8em;font-weight:600;">v1.0</span>', unsafe_allow_html=True)
    st.markdown("---")

    # ========================================================================
    # ONTOLOGY CONFIGURATION
    # ========================================================================
    st.markdown("### Ontology Configuration")

    ontology_option = st.radio(
        "Select ontology source:",
        ["Default", "Upload Custom"],
        key="ontology_option"
    )

    custom_ontology_path = None
    if ontology_option == "Upload Custom":
        uploaded_ontology = st.file_uploader(
            "Upload TTL ontology file:",
            type=['ttl', 'turtle', 'rdf'],
            key="ontology_upload"
        )
        if uploaded_ontology:
            custom_ontology_path = f"temp_ontology_{uploaded_ontology.name}"
            with open(custom_ontology_path, 'wb') as f:
                f.write(uploaded_ontology.read())
            st.success(f"✅ Loaded: {uploaded_ontology.name}")
        else:
            st.info("Upload a custom ontology file")
    else:
        default_onto = "Sui_Move_Ontology.ttl"
        if os.path.exists(default_onto):
            st.success("✅ Using default ontology")
        else:
            st.warning("Default ontology not found")

    if 'ontology_path' not in st.session_state:
        st.session_state['ontology_path'] = custom_ontology_path
    elif custom_ontology_path:
        st.session_state['ontology_path'] = custom_ontology_path

    st.markdown("---")

    # ========================================================================
    # ANALYZER CAPABILITIES
    # ========================================================================
    st.markdown("### Capabilities")
    
    with st.expander("Pattern Detection", expanded=False):
        st.markdown("""
        - Access Control
        - Circuit Breaker
        - Time Incentivization
        - Escapability
        """)
    
    with st.expander("Vulnerability Detection", expanded=False):
        st.markdown("""
        - AUTH: 4 defects
        - TIME: 4 defects
        - RES: 3 defects
        - CONS: 2 defects
        """)

# ============================================================================
# HERO HEADER
# ============================================================================
st.markdown("""
<div class="hero-container">
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
        <div>
            <h1 class="hero-title">🛡️ Sui Move Security Analyzer</h1>
            <p class="hero-subtitle">Ontology-Driven Analysis for Smart Contract Vulnerability Detection</p>
            <span class="hero-badge">Design Science Research</span>
        </div>
        <div class="institution-badge">
            <p class="institution-name">University of Macedonia</p>
            <p class="institution-type">PhD Research • Greece</p>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ============================================================================
# INPUT SECTION
# ============================================================================
st.markdown("""
<div class="section-header">
    <span class="section-icon">📝</span>
    <h2 class="section-title">Input Smart Contract</h2>
</div>
""", unsafe_allow_html=True)

input_tab1, input_tab2 = st.tabs(["Paste Code", "Upload File"])

manual_code = ""
uploaded_code = ""

with input_tab1:
    manual_code = st.text_area(
        "Paste Sui Move code:",
        height=300,
        placeholder="module example::my_contract {\n    use sui::coin::Coin;\n    \n    public struct AdminCap has key { id: UID }\n    \n    public fun protected_action(cap: &AdminCap) {\n        // Protected by capability\n    }\n}",
        label_visibility="collapsed"
    )

with input_tab2:
    uploaded_file = st.file_uploader("Choose .move or .txt file", type=['move', 'txt'])
    if uploaded_file:
        uploaded_code = uploaded_file.read().decode('utf-8')
        st.markdown(f'<div style="background:#f0fdf4; color:#166534; padding:0.9rem; border-radius:8px; border:1px solid #bbf7d0; text-align:center; font-weight:600;">✅ Loaded: {uploaded_file.name}</div>', unsafe_allow_html=True)
        with st.expander("View File Content", expanded=False):
            st.code(uploaded_code, language='rust')

user_code = uploaded_code if uploaded_code else manual_code

# ============================================================================
# ANALYZE BUTTON
# ============================================================================
st.markdown("<br>", unsafe_allow_html=True)
col1, col2, col3 = st.columns([1, 2, 1])

with col2:
    analyze_button = st.button("Run Analysis", use_container_width=True, type="primary")

# ============================================================================
# ANALYSIS EXECUTION
# ============================================================================
if analyze_button and user_code:
    progress = st.progress(0)
    status = st.empty()
    
    steps = [
        ("Loading ontology...", 15),
        ("Building knowledge graph...", 30),
        ("Detecting patterns...", 50),
        ("Scanning vulnerabilities...", 70),
        ("Generating results...", 90),
        ("Complete", 100)
    ]
    
    try:
        for step_text, step_progress in steps[:2]:
            status.text(step_text)
            progress.progress(step_progress)
            time.sleep(0.2)
        
        ontology_path = st.session_state.get('ontology_path', None)
        analyzer = ComprehensiveSuiAnalyzer(ontology_path=ontology_path)
        
        for step_text, step_progress in steps[2:4]:
            status.text(step_text)
            progress.progress(step_progress)
            time.sleep(0.15)
        
        result = analyzer.analyze_contract(user_code, "user_contract")
        
        for step_text, step_progress in steps[4:]:
            status.text(step_text)
            progress.progress(step_progress)
            time.sleep(0.15)
        
        st.session_state['analysis_result'] = result
        st.session_state['analyzer'] = analyzer
        
        status.empty()
        progress.empty()

    except Exception as e:
        st.error(f"Error: {str(e)}")
        st.exception(e)

elif analyze_button:
    st.markdown('<div style="background:#fffbeb; color:#b45309; padding:0.9rem; border-radius:8px; border:1px solid #fde68a; text-align:center; font-weight:600;">Please provide code to analyze</div>', unsafe_allow_html=True)

# ============================================================================
# RESULTS DISPLAY
# ============================================================================
if 'analysis_result' in st.session_state:
    result = st.session_state['analysis_result']
    analyzer = st.session_state['analyzer']

    st.markdown("---")
    
    # ========================================================================
    # MAIN METRICS
    # ========================================================================
    st.markdown("""
    <div class="section-header">
        <span class="section-icon">📊</span>
        <h2 class="section-title">Results Summary</h2>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="metric-card patterns">
            <p class="metric-value">{result['statistics']['patterns_detected']}</p>
            <p class="metric-label">Patterns</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card vulnerabilities">
            <p class="metric-value">{result['statistics']['vulnerabilities_found']}</p>
            <p class="metric-label">Vulnerabilities</p>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card dcr">
            <p class="metric-value">{result['statistics']['dcr_graphs_generated']}</p>
            <p class="metric-label">DCR Graphs</p>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card fixes">
            <p class="metric-value">{result['statistics']['fixes_available']}</p>
            <p class="metric-label">Fixes</p>
        </div>
        """, unsafe_allow_html=True)

    # ========================================================================
    # VULNERABILITY BREAKDOWN
    # ========================================================================
    if result['statistics']['vulnerabilities_found'] > 0:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <div class="section-header">
            <span class="section-icon">🔍</span>
            <h2 class="section-title">Vulnerability Breakdown</h2>
        </div>
        """, unsafe_allow_html=True)

        breakdown = result['statistics'].get('vulnerability_breakdown', {})

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown(f"""
            <div class="category-card">
                <span class="category-badge badge-auth">AUTH: {breakdown.get('AUTH', 0)}</span>
                <p class="category-description">Authorization</p>
            </div>
            """, unsafe_allow_html=True)

        with col2:
            st.markdown(f"""
            <div class="category-card">
                <span class="category-badge badge-time">TIME: {breakdown.get('TIME', 0)}</span>
                <p class="category-description">Temporal</p>
            </div>
            """, unsafe_allow_html=True)

        with col3:
            st.markdown(f"""
            <div class="category-card">
                <span class="category-badge badge-res">RES: {breakdown.get('RES', 0)}</span>
                <p class="category-description">Resource</p>
            </div>
            """, unsafe_allow_html=True)

        with col4:
            st.markdown(f"""
            <div class="category-card">
                <span class="category-badge badge-cons">CONS: {breakdown.get('CONS', 0)}</span>
                <p class="category-description">Constraint</p>
            </div>
            """, unsafe_allow_html=True)

    # ========================================================================
    # DETECTION METHODS
    # ========================================================================
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div class="section-header">
        <span class="section-icon">🔬</span>
        <h2 class="section-title">Detection Methods</h2>
    </div>
    """, unsafe_allow_html=True)

    methods = result['statistics'].get('detection_methods', {})
    total_detections = sum(methods.values())

    if total_detections > 0:
        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown(f"""
            <div class="method-card">
                <p class="method-count">{methods.get('capability_based', 0)}</p>
                <p class="method-name">Capability-Based</p>
                <p class="method-description">AdminCap, TreasuryCap</p>
            </div>
            """, unsafe_allow_html=True)

        with col2:
            st.markdown(f"""
            <div class="method-card">
                <p class="method-count">{methods.get('dynamic_acl', 0)}</p>
                <p class="method-name">Dynamic ACL</p>
                <p class="method-description">Table/VecSet</p>
            </div>
            """, unsafe_allow_html=True)

        with col3:
            st.markdown(f"""
            <div class="method-card">
                <p class="method-count">{methods.get('inline_auth', 0)}</p>
                <p class="method-name">Inline Auth</p>
                <p class="method-description">assert! checks</p>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No authorization patterns detected")

    # ========================================================================
    # DETAILED RESULTS TABS
    # ========================================================================
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("---")

    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Patterns", "Vulnerabilities", "DCR Graphs", "Fixes", "Ontology Reasoning"])

    with tab1:
        if result['patterns']:
            for pattern_type, count in result['patterns'].items():
                with st.expander(f"✓ {pattern_type} ({count})"):
                    st.markdown(f"**Type:** {pattern_type}")
                    st.markdown(f"**Count:** {count} function(s)")
        else:
            st.info("No patterns detected")

    with tab2:
        if result['vulnerabilities']:
            for vuln in result['vulnerabilities']:
                severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(vuln.severity.value, "⚪")
                with st.expander(f"{severity_icon} {vuln.defect_id}: {vuln.function_name}"):
                    st.markdown(f"**Severity:** {vuln.severity.value}")
                    st.markdown(f"**Category:** {vuln.category.value}")
                    st.markdown(f"**Function:** `{vuln.function_name}`")
                    st.markdown(f"**Description:** {vuln.description}")
                    if vuln.evidence:
                        st.code(vuln.evidence, language='text')
        else:
            st.success("No vulnerabilities detected")

    with tab3:
        # ==================================================================
        # DCR GRAPHS TAB - INTERACTIVE HTML
        # ==================================================================
        if result['dcr_graphs']:
            st.markdown("### Formal Business Logic Architecture")
            st.markdown("Drag nodes to interact. Use tabs to switch between detected patterns.")
            
            # Fetch the clean HTML from backend. 
            html_code = analyzer.dcr_generator.generate_interactive_html()

            # Render it directly in the Streamlit app
            components.html(html_code, height=750, scrolling=True)
        else:
            st.info("No DCR graphs generated")

    with tab4:
        if result['fix_suggestions']:
            # Group fixes by defect_id, collecting all affected functions
            grouped = {}
            for fix in result['fix_suggestions']:
                defect_id = fix['vulnerability']['defect_id']
                if defect_id not in grouped:
                    grouped[defect_id] = {
                        'fix_info': fix['fix'],
                        'vulnerability': fix['vulnerability'],
                        'affected_functions': []
                    }
                fn = fix['vulnerability'].get('function', 'unknown')
                if fn not in grouped[defect_id]['affected_functions']:
                    grouped[defect_id]['affected_functions'].append(fn)

            for defect_id, data in grouped.items():
                fix_info = data['fix_info']
                affected = ", ".join(f"`{f}`" for f in data['affected_functions'])
                with st.expander(f"Fix: {defect_id}  ({len(data['affected_functions'])} function(s) affected)"):
                    st.markdown(f"**Affected functions:** {affected}")
                    st.markdown(f"**Pattern:** {fix_info['pattern']}")
                    st.markdown(fix_info['explanation'])
                    if fix_info['example']:
                        st.code(fix_info['example'], language='rust')
        else:
            st.success("No fixes needed")

    with tab5:
        # ==================================================================
        # ONTOLOGY REASONING TAB
        # ==================================================================
        st.markdown("""
        <div class="reasoning-header">
            <p class="reasoning-title">Three-Property Semantic Reasoning Engine</p>
            <p class="reasoning-subtitle">SPARQL-based ontology-driven vulnerability detection via RDF knowledge graph</p>
        </div>
        """, unsafe_allow_html=True)

        # --- SPARQL Findings ---
        sparql_vulns = [v for v in result['vulnerabilities'] if '[SPARQL]' in v.description]
        regex_vulns = [v for v in result['vulnerabilities'] if '[SPARQL]' not in v.description]

        st.markdown(f"**SPARQL Detections: {len(sparql_vulns)}** &nbsp;|&nbsp; Regex Detections: {len(regex_vulns)} &nbsp;|&nbsp; Total: {len(result['vulnerabilities'])}")

        if sparql_vulns:
            for sv in sparql_vulns:
                severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sv.severity.value, "⚪")
                evidence_html = ""
                if sv.evidence:
                    safe_evidence = sv.evidence.replace("<", "&lt;").replace(">", "&gt;")
                    evidence_html = f'<div class="sparql-evidence">{safe_evidence}</div>'

                st.markdown(f"""
                <div class="sparql-finding">
                    <p class="sparql-finding-title">{severity_icon} {sv.defect_id} — <code>{sv.function_name}</code></p>
                    <p style="font-size:0.85rem; color:#475569; margin:0;">{sv.description}</p>
                    {evidence_html}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="sparql-empty">
                All risk-indicating operations have corresponding mitigation guards — no unmitigated risks found by SPARQL reasoning.
            </div>
            """, unsafe_allow_html=True)

        # --- SPARQL Query (collapsible) ---
        with st.expander("View SPARQL Query", expanded=False):
            st.code("""
PREFIX sui:     <http://www.sui-move-ontology.com/ontology#>
PREFIX suwc:    <http://www.sui-move-ontology.com/defects/v1#>
PREFIX pattern: <http://www.sui-move-ontology.com/patterns/v1#>
PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?funcLabel ?defect ?defectLabel ?riskOpLabel ?patternLabel
WHERE {
    # PHASE 1 — Risk Detection
    ?func sui:performsOperation ?riskOp .
    ?riskOp sui:indicatesDefectRisk ?defect .
    ?func rdfs:label ?funcLabel .
    ?defect rdfs:label ?defectLabel .
    FILTER(STRSTARTS(?defectLabel, "SUWC-"))
    ?riskOp rdfs:label ?riskOpLabel .

    # PHASE 2 — Mitigation Confirmation
    FILTER NOT EXISTS {
        ?func sui:performsOperation ?mitigOp .
        ?mitigOp sui:mitigatesDefect ?defect .
    }

    # PHASE 2b — Pattern-Protected Exclusion
    FILTER NOT EXISTS {
        ?func sui:implementsPattern ?guardPattern .
        ?guardPattern sui:addressesDefect ?defect .
    }

    # PHASE 3 — Prescriptive Remediation
    OPTIONAL {
        ?pattern sui:addressesDefect ?defect .
        ?pattern rdfs:label ?patternLabel .
    }
}
ORDER BY ?funcLabel ?defect
            """, language='sparql')

# ============================================================================
# FOOTER
# ============================================================================
st.markdown("---")
st.markdown("""
<div class="footer-container">
    <p class="footer-title">Sui Move Security Analyzer v1.0</p>
    <p class="footer-institution">University of Macedonia, Greece</p>
    <div>
        <span class="feature-pill">4 Patterns</span>
        <span class="feature-pill">13 SUWC Defects</span>
        <span class="feature-pill">SPARQL Reasoning</span>
        <span class="feature-pill">Ontology-Driven</span>
    </div>
</div>
""", unsafe_allow_html=True)