"""
REST API Server using FastAPI

Provides RESTful endpoints for command detection.
"""

from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
import numpy as np
from pathlib import Path
import sys
import uvicorn

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.features.extractor import FeatureExtractor
from src.models.model_trainer import ModelTrainer


# Pydantic models
class CommandRequest(BaseModel):
    """Request model for single command detection."""
    command: str = Field(..., description="Command string to analyze")
    model: Optional[str] = Field("ensemble", description="Model to use: rf, xgb, or ensemble")


class CommandResponse(BaseModel):
    """Response model for detection result."""
    command: str
    prediction: str
    confidence: float
    is_malicious: bool
    features: Optional[dict] = None


class BatchCommandRequest(BaseModel):
    """Request model for batch command detection."""
    commands: List[str] = Field(..., description="List of commands to analyze")
    model: Optional[str] = Field("ensemble", description="Model to use")


class BatchCommandResponse(BaseModel):
    """Response model for batch detection."""
    results: List[CommandResponse]
    summary: dict


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    models_loaded: dict


# Initialize FastAPI app
app = FastAPI(
    title="Obfuscated Command Detection API",
    description="REST API for detecting obfuscated malicious commands using Machine Learning",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global models
class ModelManager:
    """Manage ML models."""
    
    def __init__(self):
        self.extractor = FeatureExtractor()
        self.trainer = ModelTrainer()
        self.rf_model = None
        self.xgb_model = None
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models."""
        model_dir = Path(__file__).parent.parent / "models"
        
        if not model_dir.exists():
            print("Warning: No models directory found")
            return
        
        # Load Random Forest
        rf_models = sorted(model_dir.glob("random_forest_*.joblib"))
        if rf_models:
            self.rf_model = self.trainer.load_model(str(rf_models[-1]))
            print(f"Loaded Random Forest: {rf_models[-1].name}")
        
        # Load XGBoost
        xgb_models = sorted(model_dir.glob("xgboost_*.joblib"))
        if xgb_models:
            self.xgb_model = self.trainer.load_model(str(xgb_models[-1]))
            print(f"Loaded XGBoost: {xgb_models[-1].name}")
    
    def predict(self, command: str, model_type: str = "ensemble", include_features: bool = False):
        """Make prediction for a command."""
        # Extract features
        features = self.extractor.extract_features(command)
        X = np.array([list(features.values())])
        
        # Select model and predict
        if model_type == "rf":
            if self.rf_model is None:
                raise HTTPException(status_code=503, detail="Random Forest model not loaded")
            prediction = self.rf_model.predict(X)[0]
            confidence = self.rf_model.predict_proba(X)[0, 1]
        
        elif model_type == "xgb":
            if self.xgb_model is None:
                raise HTTPException(status_code=503, detail="XGBoost model not loaded")
            prediction = self.xgb_model.predict(X)[0]
            confidence = self.xgb_model.predict_proba(X)[0, 1]
        
        else:  # ensemble
            if self.rf_model is None or self.xgb_model is None:
                raise HTTPException(status_code=503, detail="Ensemble models not fully loaded")
            
            rf_proba = self.rf_model.predict_proba(X)[0, 1]
            xgb_proba = self.xgb_model.predict_proba(X)[0, 1]
            confidence = (rf_proba + xgb_proba) / 2
            prediction = 1 if confidence >= 0.5 else 0
        
        result = {
            "command": command,
            "prediction": "MALICIOUS" if prediction == 1 else "BENIGN",
            "confidence": float(confidence),
            "is_malicious": bool(prediction == 1)
        }
        
        if include_features:
            result["features"] = features
        
        return result


# Initialize model manager
model_manager = ModelManager()


# API Endpoints
@app.get("/", response_model=dict)
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Obfuscated Command Detection API",
        "version": "1.0.0",
        "endpoints": {
            "POST /detect": "Detect single command",
            "POST /detect/batch": "Detect multiple commands",
            "POST /detect/file": "Detect commands from file",
            "GET /health": "Health check",
            "GET /docs": "API documentation"
        }
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "models_loaded": {
            "random_forest": model_manager.rf_model is not None,
            "xgboost": model_manager.xgb_model is not None,
            "ensemble": model_manager.rf_model is not None and model_manager.xgb_model is not None
        }
    }


@app.post("/detect", response_model=CommandResponse)
async def detect_command(request: CommandRequest):
    """
    Detect if a single command is obfuscated/malicious.
    
    Args:
        request: CommandRequest with command string and model choice
    
    Returns:
        CommandResponse with prediction and confidence
    """
    try:
        result = model_manager.predict(
            request.command,
            request.model,
            include_features=False
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/detect/detailed", response_model=CommandResponse)
async def detect_command_detailed(request: CommandRequest):
    """
    Detect command with detailed feature information.
    
    Args:
        request: CommandRequest with command string
    
    Returns:
        CommandResponse with prediction, confidence, and features
    """
    try:
        result = model_manager.predict(
            request.command,
            request.model,
            include_features=True
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/detect/batch", response_model=BatchCommandResponse)
async def detect_batch(request: BatchCommandRequest):
    """
    Detect multiple commands at once.
    
    Args:
        request: BatchCommandRequest with list of commands
    
    Returns:
        BatchCommandResponse with results for each command
    """
    try:
        results = []
        malicious_count = 0
        
        for command in request.commands[:1000]:  # Limit to 1000 commands
            result = model_manager.predict(command, request.model)
            results.append(result)
            if result["is_malicious"]:
                malicious_count += 1
        
        return {
            "results": results,
            "summary": {
                "total": len(results),
                "malicious": malicious_count,
                "benign": len(results) - malicious_count,
                "malicious_percentage": (malicious_count / len(results) * 100) if results else 0
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/detect/file")
async def detect_file(file: UploadFile = File(...), model: str = "ensemble"):
    """
    Detect commands from uploaded file.
    
    Args:
        file: Text file with one command per line
        model: Model to use (rf, xgb, or ensemble)
    
    Returns:
        Detection results for all commands
    """
    try:
        # Read file
        content = await file.read()
        commands = content.decode('utf-8', errors='ignore').strip().split('\n')
        commands = [cmd.strip() for cmd in commands if cmd.strip()]
        
        # Detect
        results = []
        malicious_count = 0
        
        for command in commands[:1000]:  # Limit to 1000
            result = model_manager.predict(command, model)
            results.append(result)
            if result["is_malicious"]:
                malicious_count += 1
        
        return {
            "filename": file.filename,
            "results": results,
            "summary": {
                "total": len(results),
                "malicious": malicious_count,
                "benign": len(results) - malicious_count
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/models")
async def list_models():
    """List available models and their status."""
    return {
        "random_forest": {
            "loaded": model_manager.rf_model is not None,
            "type": "RandomForestClassifier"
        },
        "xgboost": {
            "loaded": model_manager.xgb_model is not None,
            "type": "XGBClassifier"
        },
        "ensemble": {
            "loaded": model_manager.rf_model is not None and model_manager.xgb_model is not None,
            "type": "Ensemble (RF + XGBoost)"
        }
    }


@app.get("/stats")
async def get_stats():
    """Get feature extractor statistics."""
    return {
        "total_features": len(model_manager.extractor.get_feature_names()),
        "feature_categories": {
            "statistical": 5,
            "entropy": 3,
            "pattern": 6,
            "character": 7,
            "structural": 12,
            "platform": 5,
            "encoding": 5
        }
    }


if __name__ == "__main__":
    print("\n" + "="*60)
    print("Starting Obfuscated Command Detection API Server")
    print("="*60)
    print("\nServer will be available at:")
    print("  - http://localhost:8000")
    print("  - Documentation: http://localhost:8000/docs")
    print("  - ReDoc: http://localhost:8000/redoc")
    print("\n" + "="*60 + "\n")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )