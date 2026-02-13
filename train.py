import sys
from pathlib import Path
import argparse


sys.path.append(str(Path(__file__).parent))

from src.data.dataset_loader import DatasetLoader
from src.features.extractor import FeatureExtractor
from src.models.model_trainer import ModelTrainer
import matplotlib.pyplot as plt
import seaborn as sns


def main(args):
    """Main training pipeline."""
    
    print("\n" + "="*70)
    print(" OBFUSCATED COMMAND DETECTION - MODEL TRAINING")
    print("="*70)
    
    # Load/Create Dataset
    print("\n[STEP 1/5] Loading Dataset...")
    print("-" * 70)
    
    loader = DatasetLoader(data_dir="data")
    
    if args.regenerate_data:
        print("Regenerating dataset...")
        train_df, test_df = loader.get_train_test_split()
    else:
        train_df, test_df = loader.get_train_test_split()
    
    print(f"\nDataset Statistics:")
    stats = loader.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print(f"\nTraining samples: {len(train_df)}")
    print(f"Test samples: {len(test_df)}")
    
    # Display sample commands
    print("\nSample malicious commands:")
    for cmd in train_df[train_df['label'] == 1]['command'].head(3):
        print(f"  - {cmd[:80]}...")
    
    print("\nSample benign commands:")
    for cmd in train_df[train_df['label'] == 0]['command'].head(3):
        print(f"  - {cmd[:80]}...")
    
    # Feature Extraction
    print("\n[STEP 2/5] Extracting Features...")
    print("-" * 70)
    
    extractor = FeatureExtractor()
    
    print("Extracting training features...")
    X_train = extractor.extract_batch(train_df['command'].tolist())
    y_train = train_df['label'].values
    
    print("Extracting test features...")
    X_test = extractor.extract_batch(test_df['command'].tolist())
    y_test = test_df['label'].values
    
    feature_names = extractor.get_feature_names()
    
    print(f"\nFeature extraction complete:")
    print(f"  Number of features: {len(feature_names)}")
    print(f"  Training set shape: {X_train.shape}")
    print(f"  Test set shape: {X_test.shape}")
    
    # Train Random Forest
    print("\n[STEP 3/5] Training Random Forest...")
    print("-" * 70)
    
    trainer = ModelTrainer(model_dir="models")
    
    rf_model = trainer.train_random_forest(
        X_train, y_train,
        feature_names,
        hyperparameter_tuning=args.tune
    )
    
    # Evaluate Random Forest
    rf_metrics = trainer.evaluate_model(rf_model, X_test, y_test, "Random Forest")
    
    # Get feature importance
    rf_importance = trainer.get_feature_importance(rf_model, "Random Forest", top_n=20)
    
    # Save Random Forest
    trainer.save_model(rf_model, "random_forest", rf_metrics)
    
    # Train XGBoost
    print("\n[STEP 4/5] Training XGBoost...")
    print("-" * 70)
    
    xgb_model = trainer.train_xgboost(
        X_train, y_train,
        feature_names,
        hyperparameter_tuning=args.tune
    )
    
    # Evaluate XGBoost
    xgb_metrics = trainer.evaluate_model(xgb_model, X_test, y_test, "XGBoost")
    
    # Get feature importance
    xgb_importance = trainer.get_feature_importance(xgb_model, "XGBoost", top_n=20)
    
    # Save XGBoost
    trainer.save_model(xgb_model, "xgboost", xgb_metrics)
    
    # Create Ensemble
    print("\n[STEP 5/5] Creating Ensemble Model...")
    print("-" * 70)
    
    ensemble_pred, ensemble_metrics = trainer.create_ensemble(X_test, y_test)
    
    # Comparison Table
    print("\n" + "="*70)
    print("MODEL COMPARISON")
    print("="*70)
    
    print(f"\n{'Metric':<20} {'Random Forest':<20} {'XGBoost':<20} {'Ensemble':<20}")
    print("-" * 80)
    
    metrics_to_compare = ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc']
    
    for metric in metrics_to_compare:
        rf_val = rf_metrics.get(metric, 0)
        xgb_val = xgb_metrics.get(metric, 0)
        ens_val = ensemble_metrics.get(metric, 0)
        
        print(f"{metric.upper():<20} {rf_val:>18.4f} {xgb_val:>18.4f} {ens_val:>18.4f}")
    
    # Visualizations
    if args.visualize:
        print("\n[BONUS] Creating Visualizations...")
        print("-" * 70)
        
        # Feature importance comparison
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Random Forest
        top_rf = rf_importance.head(15)
        ax1.barh(top_rf['feature'], top_rf['importance'])
        ax1.set_xlabel('Importance')
        ax1.set_title('Random Forest - Top 15 Features')
        ax1.invert_yaxis()
        
        # XGBoost
        top_xgb = xgb_importance.head(15)
        ax2.barh(top_xgb['feature'], top_xgb['importance'])
        ax2.set_xlabel('Importance')
        ax2.set_title('XGBoost - Top 15 Features')
        ax2.invert_yaxis()
        
        plt.tight_layout()
        plt.savefig('models/feature_importance_comparison.png', dpi=300, bbox_inches='tight')
        print("✓ Feature importance plot saved to models/feature_importance_comparison.png")
        
        # Model comparison
        fig, ax = plt.subplots(figsize=(10, 6))
        
        models = ['Random Forest', 'XGBoost', 'Ensemble']
        metrics_dict = {
            'Accuracy': [rf_metrics['accuracy'], xgb_metrics['accuracy'], ensemble_metrics['accuracy']],
            'Precision': [rf_metrics['precision'], xgb_metrics['precision'], ensemble_metrics['precision']],
            'Recall': [rf_metrics['recall'], xgb_metrics['recall'], ensemble_metrics['recall']],
            'F1 Score': [rf_metrics['f1_score'], xgb_metrics['f1_score'], ensemble_metrics['f1_score']],
        }
        
        x = range(len(models))
        width = 0.2
        
        for i, (metric, values) in enumerate(metrics_dict.items()):
            offset = width * i
            ax.bar([p + offset for p in x], values, width, label=metric)
        
        ax.set_xlabel('Model')
        ax.set_ylabel('Score')
        ax.set_title('Model Performance Comparison')
        ax.set_xticks([p + width * 1.5 for p in x])
        ax.set_xticklabels(models)
        ax.legend()
        ax.set_ylim(0.9, 1.0)
        
        plt.tight_layout()
        plt.savefig('models/model_comparison.png', dpi=300, bbox_inches='tight')
        print("✓ Model comparison plot saved to models/model_comparison.png")
    
    # Summary
    print("\n" + "="*70)
    print("TRAINING COMPLETE!")
    print("="*70)
    print("\n✓ All models trained and saved")
    print("✓ Models are ready for deployment")
    print("\nNext steps:")
    print("  1. Test the web demo:  python app/web_demo.py")
    print("  2. Start the API:      python app/api_server.py")
    print("  3. Launch dashboard:   streamlit run app/dashboard.py")
    print("  4. Use CLI:            python cli.py detect 'your command here'")
    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train obfuscated command detection models"
    )
    
    parser.add_argument(
        '--tune',
        action='store_true',
        help='Perform hyperparameter tuning (slower but better results)'
    )
    
    parser.add_argument(
        '--regenerate-data',
        action='store_true',
        help='Regenerate the dataset from scratch'
    )
    
    parser.add_argument(
        '--visualize',
        action='store_true',
        help='Create visualization plots'
    )
    
    args = parser.parse_args()
    
    main(args)