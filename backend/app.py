from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
from feature_extractor import extract_features

# Load the trained machine learning model
model = joblib.load("model.pkl")

# Create FastAPI application
app = FastAPI(title="SnowShield API")

# Enable CORS so your frontend (scan.html) can call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Allow all origins during development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request body format
class ScanRequest(BaseModel):
    url: str


# Test endpoint
@app.get("/")
def home():
    return {"message": "SnowShield API is running"}


# Main scanning endpoint
@app.post("/scan")
def scan_link(request: ScanRequest):
    url = request.url.strip()

    # Convert URL into numeric features
    features = [extract_features(url)]

    # Predict: 0 = safe, 1 = phishing
    prediction = int(model.predict(features)[0])

    # Get probability scores
    probabilities = model.predict_proba(features)[0]
    classes = list(model.classes_)

    # Find phishing probability (class 1)
    if 1 in classes:
        phishing_index = classes.index(1)
        phishing_probability = float(probabilities[phishing_index])
    else:
        phishing_probability = 0.0

    # Convert probability to risk score out of 100
    risk_score = round(phishing_probability * 100)

    # Decide final status and explanation
    if prediction == 0:
        status = "safe"
        signals = [
            "No strong phishing indicators detected",
            "Domain structure appears normal",
            "URL passed machine learning analysis"
        ]
    elif risk_score < 80:
        status = "suspicious"
        signals = [
            "Some phishing indicators detected",
            "Proceed with caution",
            "Avoid entering sensitive information"
        ]
    else:
        status = "dangerous"
        signals = [
            "Strong phishing indicators detected",
            "Do not enter passwords or payment details",
            "Opening this link may be unsafe"
        ]

    # Return JSON response
    return {
        "url": url,
        "status": status,
        "risk_score": risk_score,
        "signals": signals
    }