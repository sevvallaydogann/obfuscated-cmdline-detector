import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sys
from pathlib import Path
import time

sys.path.append(str(Path(__file__).parent.parent))

from src.features.extractor import FeatureExtractor
from src.models.model_trainer import ModelTrainer


# Page configuration
st.set_page_config(
    page_title="Command Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .malicious {
        color: #d62728;
        font-weight: bold;
    }
    .benign {
        color: #2ca02c;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def load_models():
    extractor = FeatureExtractor()
    trainer = ModelTrainer()
    
    model_dir = Path(__file__).parent.parent / "models"
    
    rf_model = None
    xgb_model = None
    
    if model_dir.exists():
        rf_models = sorted(model_dir.glob("random_forest_*.joblib"))
        xgb_models = sorted(model_dir.glob("xgboost_*.joblib"))
        
        if rf_models:
            rf_model = trainer.load_model(str(rf_models[-1]))
        if xgb_models:
            xgb_model = trainer.load_model(str(xgb_models[-1]))
    
    return extractor, rf_model, xgb_model


def predict_command(command, extractor, rf_model, xgb_model):
    features = extractor.extract_features(command)
    X = np.array([list(features.values())])
    
    if rf_model and xgb_model:
        rf_proba = rf_model.predict_proba(X)[0, 1]
        xgb_proba = xgb_model.predict_proba(X)[0, 1]
        confidence = (rf_proba + xgb_proba) / 2
        prediction = 1 if confidence >= 0.5 else 0
    elif xgb_model:
        prediction = xgb_model.predict(X)[0]
        confidence = xgb_model.predict_proba(X)[0, 1]
    else:
        return None, None, None
    
    return prediction, confidence, features


def main():
    """Main dashboard application."""
    
    st.markdown('<div class="main-header">🛡️ Obfuscated Command Detection Dashboard</div>', unsafe_allow_html=True)
    
    extractor, rf_model, xgb_model = load_models()
    
    if rf_model is None and xgb_model is None:
        st.error("❌ No models loaded. Please train models first.")
        st.info("Run: `python cli.py train --model all`")
        return
    
    st.sidebar.header("⚙️ Configuration")
    
    detection_mode = st.sidebar.radio(
        "Detection Mode",
        ["Real-time Monitor", "Batch Analysis", "Statistics"]
    )
    
    # Initialize session state
    if 'detection_history' not in st.session_state:
        st.session_state.detection_history = []
    
    if 'malicious_count' not in st.session_state:
        st.session_state.malicious_count = 0
    
    if 'benign_count' not in st.session_state:
        st.session_state.benign_count = 0
    
    # Real-time Monitor Mode
    if detection_mode == "Real-time Monitor":
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total Analyzed",
                len(st.session_state.detection_history),
                delta=None
            )
        
        with col2:
            st.metric(
                "Malicious",
                st.session_state.malicious_count,
                delta=None,
                delta_color="inverse"
            )
        
        with col3:
            st.metric(
                "Benign",
                st.session_state.benign_count,
                delta=None
            )
        
        with col4:
            detection_rate = (st.session_state.malicious_count / len(st.session_state.detection_history) * 100) if st.session_state.detection_history else 0
            st.metric(
                "Detection Rate",
                f"{detection_rate:.1f}%"
            )
        
        st.markdown("---")
        
        # Input section
        st.subheader("🔍 Analyze Command")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            command_input = st.text_area(
                "Enter command to analyze",
                height=100,
                placeholder="e.g., powershell -enc JABhAD0AJwBoAGUAbABsAG8AJwA7ACAAJABhAA=="
            )
        
        with col2:
            st.write("")
            st.write("")
            analyze_btn = st.button("🔍 Analyze", use_container_width=True)
            clear_btn = st.button("🗑️ Clear History", use_container_width=True)
        
        if clear_btn:
            st.session_state.detection_history = []
            st.session_state.malicious_count = 0
            st.session_state.benign_count = 0
            st.rerun()
        
        if analyze_btn and command_input:
            with st.spinner("Analyzing..."):
                prediction, confidence, features = predict_command(
                    command_input, extractor, rf_model, xgb_model
                )
                
                if prediction is not None:
                    # Add to history
                    result = {
                        'timestamp': datetime.now(),
                        'command': command_input[:100],
                        'prediction': 'MALICIOUS' if prediction == 1 else 'BENIGN',
                        'confidence': confidence,
                        'features': features
                    }
                    st.session_state.detection_history.insert(0, result)
                    
                    if prediction == 1:
                        st.session_state.malicious_count += 1
                    else:
                        st.session_state.benign_count += 1
                    
                    # Display result
                    if prediction == 1:
                        st.error(f"🚨 **MALICIOUS** - Confidence: {confidence*100:.1f}%")
                    else:
                        st.success(f"✅ **BENIGN** - Confidence: {(1-confidence)*100:.1f}%")
                    
                    # Feature breakdown
                    with st.expander("📊 Feature Analysis"):
                        sorted_features = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write("**Top Features:**")
                            for name, value in sorted_features[:10]:
                                st.text(f"{name}: {value:.4f}")
                        
                        with col2:
                            # Feature importance plot
                            top_features = dict(sorted_features[:10])
                            fig = px.bar(
                                x=list(top_features.values()),
                                y=list(top_features.keys()),
                                orientation='h',
                                title="Top 10 Features"
                            )
                            fig.update_layout(height=300)
                            st.plotly_chart(fig, use_container_width=True)
        
        # Detection history
        if st.session_state.detection_history:
            st.markdown("---")
            st.subheader("📜 Detection History")
            
            # Create dataframe
            history_df = pd.DataFrame([
                {
                    'Time': r['timestamp'].strftime('%H:%M:%S'),
                    'Command': r['command'],
                    'Result': r['prediction'],
                    'Confidence': f"{r['confidence']*100:.1f}%"
                }
                for r in st.session_state.detection_history[:50]
            ])
            
            st.dataframe(
                history_df,
                use_container_width=True,
                hide_index=True
            )
            
            # Timeline chart
            st.subheader("📈 Detection Timeline")
            
            timeline_data = []
            for r in st.session_state.detection_history[:50]:
                timeline_data.append({
                    'Time': r['timestamp'],
                    'Type': r['prediction'],
                    'Value': 1
                })
            
            if timeline_data:
                timeline_df = pd.DataFrame(timeline_data)
                fig = px.scatter(
                    timeline_df,
                    x='Time',
                    y='Value',
                    color='Type',
                    color_discrete_map={'MALICIOUS': 'red', 'BENIGN': 'green'},
                    title="Detection Timeline"
                )
                fig.update_layout(yaxis_visible=False, yaxis_showticklabels=False)
                st.plotly_chart(fig, use_container_width=True)
    
    # Batch Analysis Mode
    elif detection_mode == "Batch Analysis":
        st.subheader("📦 Batch Command Analysis")
        
        uploaded_file = st.file_uploader(
            "Upload a text file with commands (one per line)",
            type=['txt']
        )
        
        if uploaded_file:
            commands = uploaded_file.read().decode('utf-8').strip().split('\n')
            commands = [cmd.strip() for cmd in commands if cmd.strip()]
            
            st.info(f"Found {len(commands)} commands")
            
            if st.button("🔍 Analyze All"):
                progress_bar = st.progress(0)
                results = []
                
                for i, cmd in enumerate(commands[:100]):
                    prediction, confidence, features = predict_command(
                        cmd, extractor, rf_model, xgb_model
                    )
                    
                    if prediction is not None:
                        results.append({
                            'Command': cmd[:80] + '...' if len(cmd) > 80 else cmd,
                            'Prediction': 'MALICIOUS' if prediction == 1 else 'BENIGN',
                            'Confidence': f"{confidence*100:.1f}%"
                        })
                    
                    progress_bar.progress((i + 1) / min(len(commands), 100))
                
                # Display results
                results_df = pd.DataFrame(results)
                
                # Summary
                malicious = sum(1 for r in results if r['Prediction'] == 'MALICIOUS')
                benign = len(results) - malicious
                
                col1, col2, col3 = st.columns(3)
                col1.metric("Total", len(results))
                col2.metric("Malicious", malicious)
                col3.metric("Benign", benign)
                
                # Results table
                st.dataframe(results_df, use_container_width=True, hide_index=True)
                
                # Pie chart
                fig = px.pie(
                    values=[malicious, benign],
                    names=['Malicious', 'Benign'],
                    title="Detection Distribution",
                    color_discrete_sequence=['#d62728', '#2ca02c']
                )
                st.plotly_chart(fig, use_container_width=True)
    
    # Statistics Mode
    else:
        st.subheader("📊 System Statistics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.info("**Model Information**")
            st.write(f"Random Forest: {'✅ Loaded' if rf_model else '❌ Not Loaded'}")
            st.write(f"XGBoost: {'✅ Loaded' if xgb_model else '❌ Not Loaded'}")
            st.write(f"Total Features: {len(extractor.get_feature_names())}")
        
        with col2:
            st.info("**Session Statistics**")
            st.write(f"Commands Analyzed: {len(st.session_state.detection_history)}")
            st.write(f"Malicious Detected: {st.session_state.malicious_count}")
            st.write(f"Benign Detected: {st.session_state.benign_count}")
        
        if st.session_state.detection_history:
            st.markdown("---")
            st.subheader("Confidence Distribution")
            
            confidences = [r['confidence'] for r in st.session_state.detection_history]
            
            fig = px.histogram(
                x=confidences,
                nbins=20,
                title="Confidence Score Distribution",
                labels={'x': 'Confidence', 'y': 'Count'}
            )
            st.plotly_chart(fig, use_container_width=True)


if __name__ == "__main__":
    main()