#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path


def run_command(cmd, description):
    """Run a shell command and print status."""
    print(f"\n{'='*70}")
    print(f"⚙️  {description}")
    print(f"{'='*70}")
    
    result = subprocess.run(cmd, shell=True, capture_output=False)
    
    if result.returncode != 0:
        print(f"❌ Error: {description} failed!")
        return False
    
    print(f"✅ {description} completed successfully!")
    return True


def main():
    """Main setup process."""
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║     🛡️  OBFUSCATED COMMAND DETECTION - SETUP WIZARD             ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required!")
        sys.exit(1)
    
    print(f"✅ Python version: {sys.version.split()[0]}")
    
    # Create necessary directories
    print("\n📁 Creating directories...")
    directories = ['data', 'models', 'logs', 'outputs']
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {directory}/")
    
    # Install dependencies
    if not run_command(
        f"{sys.executable} -m pip install -r requirements.txt",
        "Installing dependencies"
    ):
        return
    
    # Create dataset
    print("\n" + "="*70)
    print("📊 Dataset Creation")
    print("="*70)
    print("\nWould you like to:")
    print("  1. Generate synthetic dataset (recommended for testing)")
    print("  2. Skip dataset creation (use existing data)")
    
    choice = input("\nChoice (1/2): ").strip()
    
    if choice == "1":
        if not run_command(
            f"{sys.executable} -c \"from src.data.dataset_loader import DatasetLoader; loader = DatasetLoader(); loader.load_or_create_dataset(use_cache=False)\"",
            "Generating synthetic dataset"
        ):
            return
    
    # Train models
    print("\n" + "="*70)
    print("🤖 Model Training")
    print("="*70)
    print("\nWould you like to:")
    print("  1. Quick training (default parameters, ~5-10 minutes)")
    print("  2. Full training with tuning (optimized, ~30-60 minutes)")
    print("  3. Skip training")
    
    choice = input("\nChoice (1/2/3): ").strip()
    
    if choice == "1":
        if not run_command(
            f"{sys.executable} train.py --visualize",
            "Training models (quick mode)"
        ):
            return
    elif choice == "2":
        if not run_command(
            f"{sys.executable} train.py --tune --visualize",
            "Training models (full mode with hyperparameter tuning)"
        ):
            return
    
    # Success message
    print("""
    
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║                    ✅ SETUP COMPLETE! ✅                         ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    
    🚀 Your obfuscated command detection system is ready!
    
    Quick Start Commands:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    🌐 Web Demo (Interactive UI):
       python app/web_demo.py
       Then open: http://localhost:7860
    
    💻 Command Line Interface:
       python cli.py detect "your command here"
       python cli.py detect-file commands.txt
    
    🔌 REST API Server:
       python app/api_server.py
       API docs: http://localhost:8000/docs
    
    📊 Dashboard (Real-time monitoring):
       streamlit run app/dashboard.py
       Dashboard: http://localhost:8501
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    📚 Documentation:
       - README.md for detailed information
       - Check notebooks/ for examples
       - See tests/ for usage examples
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Setup failed with error: {e}")
        sys.exit(1)