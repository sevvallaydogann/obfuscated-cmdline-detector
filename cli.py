#!/usr/bin/env python3

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from pathlib import Path
import sys
import json

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.features.extractor import FeatureExtractor
from src.data.dataset_loader import DatasetLoader
from src.models.model_trainer import ModelTrainer
import numpy as np

console = Console()


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    🛡️ Obfuscated Command Line Detection CLI
    
    Detect malicious obfuscated commands using Machine Learning.
    """
    pass


@cli.command()
@click.argument('command', type=str)
@click.option('--model', '-m', type=click.Choice(['rf', 'xgb', 'ensemble']), default='ensemble',
              help='Model to use for detection')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed feature information')
def detect(command, model, verbose):
    """
    Detect if a single COMMAND is obfuscated/malicious.
    
    Example:
        cli.py detect "powershell -enc BASE64STRING"
    """
    console.print("\n[bold blue]🔍 Analyzing command...[/bold blue]\n")
    
    # Initialize
    extractor = FeatureExtractor()
    trainer = ModelTrainer()
    
    # Load models
    model_dir = Path("models")
    if not model_dir.exists():
        console.print("[red]❌ Models directory not found. Please train models first.[/red]")
        console.print("Run: [cyan]python cli.py train[/cyan]")
        return
    
    try:
        # Find latest models
        if model in ['rf', 'ensemble']:
            rf_models = sorted(model_dir.glob("random_forest_*.joblib"))
            if rf_models:
                rf_model = trainer.load_model(str(rf_models[-1]))
        
        if model in ['xgb', 'ensemble']:
            xgb_models = sorted(model_dir.glob("xgboost_*.joblib"))
            if xgb_models:
                xgb_model = trainer.load_model(str(xgb_models[-1]))
    except Exception as e:
        console.print(f"[red]Error loading models: {e}[/red]")
        return
    
    # Extract features
    features = extractor.extract_features(command)
    X = np.array([list(features.values())])
    
    # Make prediction
    if model == 'ensemble':
        rf_proba = rf_model.predict_proba(X)[0, 1]
        xgb_proba = xgb_model.predict_proba(X)[0, 1]
        confidence = (rf_proba + xgb_proba) / 2
        prediction = 1 if confidence >= 0.5 else 0
    elif model == 'rf':
        prediction = rf_model.predict(X)[0]
        confidence = rf_model.predict_proba(X)[0, 1]
    else:  # xgb
        prediction = xgb_model.predict(X)[0]
        confidence = xgb_model.predict_proba(X)[0, 1]
    
    # Display results
    console.print(f"[bold]Command:[/bold] {command[:100]}{'...' if len(command) > 100 else ''}\n")
    
    if prediction == 1:
        console.print("[bold red]🚨 MALICIOUS (Obfuscated)[/bold red]")
    else:
        console.print("[bold green]✅ BENIGN[/bold green]")
    
    console.print(f"[bold]Confidence:[/bold] {confidence*100:.2f}%\n")
    
    # Detailed information
    if verbose:
        table = Table(title="Top 10 Features")
        table.add_column("Feature", style="cyan")
        table.add_column("Value", style="magenta", justify="right")
        
        sorted_features = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)
        for name, value in sorted_features[:10]:
            table.add_row(name, f"{value:.4f}")
        
        console.print(table)


@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for results (JSON)')
@click.option('--model', '-m', type=click.Choice(['rf', 'xgb', 'ensemble']), default='ensemble')
def detect_file(filepath, output, model):
    """
    Detect commands from a file (one command per line).
    
    Example:
        cli.py detect-file commands.txt -o results.json
    """
    console.print(f"\n[bold blue]📄 Processing file: {filepath}[/bold blue]\n")
    
    # Read commands
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        commands = [line.strip() for line in f if line.strip()]
    
    console.print(f"Found {len(commands)} commands\n")
    
    # Initialize
    extractor = FeatureExtractor()
    trainer = ModelTrainer()
    
    # Load model
    model_dir = Path("models")
    if model in ['rf', 'ensemble']:
        rf_models = sorted(model_dir.glob("random_forest_*.joblib"))
        if rf_models:
            rf_model = trainer.load_model(str(rf_models[-1]))
    
    if model in ['xgb', 'ensemble']:
        xgb_models = sorted(model_dir.glob("xgboost_*.joblib"))
        if xgb_models:
            xgb_model = trainer.load_model(str(xgb_models[-1]))
    
    # Process commands
    results = []
    malicious_count = 0
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Analyzing...", total=len(commands))
        
        for cmd in commands:
            features = extractor.extract_features(cmd)
            X = np.array([list(features.values())])
            
            if model == 'ensemble':
                rf_proba = rf_model.predict_proba(X)[0, 1]
                xgb_proba = xgb_model.predict_proba(X)[0, 1]
                confidence = (rf_proba + xgb_proba) / 2
                prediction = 1 if confidence >= 0.5 else 0
            elif model == 'rf':
                prediction = rf_model.predict(X)[0]
                confidence = rf_model.predict_proba(X)[0, 1]
            else:
                prediction = xgb_model.predict(X)[0]
                confidence = xgb_model.predict_proba(X)[0, 1]
            
            if prediction == 1:
                malicious_count += 1
            
            results.append({
                'command': cmd,
                'prediction': 'MALICIOUS' if prediction == 1 else 'BENIGN',
                'confidence': float(confidence)
            })
            
            progress.update(task, advance=1)
    
    # Display summary
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Total commands: {len(commands)}")
    console.print(f"  [red]Malicious: {malicious_count}[/red]")
    console.print(f"  [green]Benign: {len(commands) - malicious_count}[/green]")
    
    # Save results
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[green]✓ Results saved to {output}[/green]")


@cli.command()
@click.option('--model', '-m', type=click.Choice(['rf', 'xgb', 'all']), default='all',
              help='Which model to train')
@click.option('--tune', is_flag=True, help='Perform hyperparameter tuning')
@click.option('--samples', '-n', type=int, default=50000, help='Number of samples to generate')
def train(model, tune, samples):
    """
    Train detection models.
    
    Example:
        cli.py train --model all --tune
    """
    console.print("\n[bold blue]🚀 Starting model training...[/bold blue]\n")
    
    # Load/create dataset
    console.print("[cyan]Loading dataset...[/cyan]")
    loader = DatasetLoader()
    train_df, test_df = loader.get_train_test_split()
    
    console.print(f"Training samples: {len(train_df)}")
    console.print(f"Test samples: {len(test_df)}\n")
    
    # Extract features
    console.print("[cyan]Extracting features...[/cyan]")
    extractor = FeatureExtractor()
    
    X_train = extractor.extract_batch(train_df['command'].tolist())
    y_train = train_df['label'].values
    X_test = extractor.extract_batch(test_df['command'].tolist())
    y_test = test_df['label'].values
    
    console.print(f"Feature dimension: {X_train.shape[1]}\n")
    
    # Train models
    trainer = ModelTrainer()
    
    if model in ['rf', 'all']:
        console.print("[bold cyan]Training Random Forest...[/bold cyan]")
        rf_model = trainer.train_random_forest(
            X_train, y_train, 
            extractor.get_feature_names(),
            hyperparameter_tuning=tune
        )
        
        # Evaluate
        rf_metrics = trainer.evaluate_model(rf_model, X_test, y_test, "Random Forest")
        
        # Save
        trainer.save_model(rf_model, "random_forest", rf_metrics)
        
        # Feature importance
        trainer.get_feature_importance(rf_model, "Random Forest")
    
    if model in ['xgb', 'all']:
        console.print("\n[bold cyan]Training XGBoost...[/bold cyan]")
        xgb_model = trainer.train_xgboost(
            X_train, y_train,
            extractor.get_feature_names(),
            hyperparameter_tuning=tune
        )
        
        # Evaluate
        xgb_metrics = trainer.evaluate_model(xgb_model, X_test, y_test, "XGBoost")
        
        # Save
        trainer.save_model(xgb_model, "xgboost", xgb_metrics)
        
        # Feature importance
        trainer.get_feature_importance(xgb_model, "XGBoost")
    
    if model == 'all':
        # Ensemble
        console.print("\n[bold cyan]Creating Ensemble...[/bold cyan]")
        ensemble_pred, ensemble_metrics = trainer.create_ensemble(X_test, y_test)
    
    console.print("\n[bold green]✓ Training complete![/bold green]")


@cli.command()
def stats():
    """Show dataset statistics."""
    console.print("\n[bold blue]📊 Dataset Statistics[/bold blue]\n")
    
    loader = DatasetLoader()
    stats = loader.get_statistics()
    
    table = Table(title="Dataset Overview")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta", justify="right")
    
    for key, value in stats.items():
        if isinstance(value, dict):
            value = ", ".join(f"{k}: {v}" for k, v in value.items())
        table.add_row(str(key).replace('_', ' ').title(), str(value))
    
    console.print(table)


@cli.command()
def list_models():
    """List available trained models."""
    console.print("\n[bold blue]🤖 Available Models[/bold blue]\n")
    
    model_dir = Path("models")
    if not model_dir.exists():
        console.print("[yellow]No models found. Train models first.[/yellow]")
        return
    
    rf_models = sorted(model_dir.glob("random_forest_*.joblib"))
    xgb_models = sorted(model_dir.glob("xgboost_*.joblib"))
    
    if rf_models:
        console.print("[bold cyan]Random Forest Models:[/bold cyan]")
        for model in rf_models:
            console.print(f"  • {model.name}")
    
    if xgb_models:
        console.print("\n[bold cyan]XGBoost Models:[/bold cyan]")
        for model in xgb_models:
            console.print(f"  • {model.name}")


if __name__ == '__main__':
    cli()