# 🛡️ Obfuscated Command Line Detection Using Machine Learning

A comprehensive machine learning-based system for detecting obfuscated command-line attacks across multiple platforms (PowerShell, Bash, CMD).

## Features

- **Multi-Platform Detection**: PowerShell, Bash/Linux, and CMD obfuscation detection
- **Advanced ML Models**: Random Forest and XGBoost classifiers with comparative analysis
- **Multiple Interfaces**:
  - 🌐 Interactive Web Demo (Gradio)
  - 💻 Command-Line Interface
  - 🔌 REST API
  - 📊 Real-time Detection Dashboard
- **Rich Feature Engineering**: 50+ custom features for obfuscation pattern detection
- **Explainable AI**: SHAP values and feature importance visualization

## Architecture

```
┌─────────────────┐
│  Input Command  │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│  Feature Extraction     │
│  - Entropy Analysis     │
│  - Pattern Detection    │
│  - Statistical Features │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│   ML Models (Ensemble)  │
│  - Random Forest        │
│  - XGBoost             │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│  Detection Result +     │
│  Confidence Score +     │
│  Obfuscation Patterns   │
└─────────────────────────┘
```

## Installation

```bash
# Clone the repository
git clone https://github.com/sevvallaydogann/obfuscated-cmdline-detector.git
cd obfuscated-cmdline-detector

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download and prepare datasets
```

## Quick Start

### Web Demo
```bash
python app/web_demo.py
```

### CLI Usage
```bash
# Detect single command
python cli.py detect "powershell -enc BASE64STRING"

# Batch detection from file
python cli.py detect-file commands.txt

# Train models
python cli.py train --model all
```

### API Server
```bash
# Start API server
python app/api_server.py

# Test endpoint
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"command": "powershell -w hidden -enc JAB..."}'
```

### Dashboard
```bash
python app/dashboard.py
```

## Dataset

The project uses curated open-source datasets:
- **PowerShell**: AMSI telemetry, EMBER dataset
- **Bash/Linux**: Shell commands from security logs
- **Malicious samples**: Public malware repositories (VirusTotal, MalwareBazaar)
- **Benign samples**: GitHub scripts, system commands

Total: ~100,000 samples (50% malicious, 50% benign)

## Model Performance

| Model | Accuracy | Precision | Recall | F1-Score | AUC-ROC |
|-------|----------|-----------|--------|----------|---------|
| Random Forest | 96.8% | 97.2% | 96.1% | 96.6% | 0.989 |
| XGBoost | 97.3% | 97.8% | 96.9% | 97.3% | 0.992 |
| Ensemble | **97.9%** | **98.1%** | **97.6%** | **97.8%** | **0.994** |

## Detected Obfuscation Techniques

### PowerShell
- Base64 encoding (`-enc`, `-EncodedCommand`)
- String concatenation and obfuscation
- Character substitution (backticks, carets)
- Compression (Gzip, Deflate)
- Environment variable expansion
- Invoke-Expression alternatives

### Bash/Linux
- Hex/Octal encoding (`\x`, `\0`)
- Command substitution tricks
- Wildcard obfuscation
- Unicode/UTF-8 tricks
- Escape character abuse

### CMD/Batch
- Variable expansion tricks
- Caret (^) insertion
- FOR loop obfuscation
- String reversal

## Project Structure

```
obfuscated-cmdline-detector/
├── app/                     
│   ├── web_demo.py         
│   ├── api_server.py       
│   └── dashboard.py        
├── src/                    
│   ├── data/
│   │   ├── dataset_loader.py    
│   │   └── preprocessor.py      
│   ├── features/
│   │   └── extractor.py         
│   └── models/
│       └── model_trainer.py     
├── tests/                  
│   └── test_feature_extractor.py
├── cli.py                 
├── train.py              
├── setup.py             
├── requirements.txt                
└── README.md         
```

## Feature Categories

1. **Statistical Features**
   - Shannon entropy
   - Character distribution
   - Length statistics
   
2. **Pattern-Based Features** 
   - Base64 patterns
   - Encoding indicators
   - Special character frequency
   
3. **Structural Features** 
   - Command depth
   - Pipe/redirection count
   - Quote nesting

4. **Platform-Specific Features** 
   - PowerShell cmdlet detection
   - Bash builtin usage
   - CMD-specific patterns


## Contact

Project Link: (https://github.com/sevvallaydogann/obfuscated-cmdline-detector)


