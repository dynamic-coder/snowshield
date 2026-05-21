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
# Main scanning endpoint
@app.post("/scan")
def scan_link(request: ScanRequest):
    url = request.url.strip().lower()

    # =========================================
    # Adult / NSFW Detection
    # =========================================
    adult_keywords = [
        "porn",
        "xxx",
        "sex",
        "adult",
        "nsfw",
        "xvideos",
        "xnxx",
        "redtube",
        "youporn",
        "hentai",
        "brazzers",
        "pornhub",
        "sexvideo",
        "hardcore",
        "camgirl",
        "webcam",
        "escort",
        "nude",
        "naked",
        "milf",
        "onlyfans",
        "blowjob",
        "anal",
        "fetish",
        "bdsm",
        "erotic",
        "18plus",
        "18+",
        "strip",
        "camsex",
        "livejasmin",
        "spankbang",
        "rule34",
        "fap",
        "fucking",
        "boobs",
        "pussy",
        "dick",
        "cum",
        "deepthroat",
        "gangbang",
        "threesome",
        "incest",
        "harem",
        "waifu",
        "ecchi",
        "jav",
        "nsfwchat",
        "sexchat",
        "land",
        "chut",
        "spank",
        "desikaka",
        "lund",
        "chudai",
        "eporner",
        "dinotube",
        "hamster",
        "xhamster",
        "pucchi",
        "bulla",
        "nigga"
    ]

    if any(keyword in url for keyword in adult_keywords):
        return {
            "url": url,
            "status": "dangerous",
            "risk_score": 98,
            "signals": [
                "Adult or NSFW content detected",
                "Website may contain explicit material",
                "Access blocked by SnowShield"
            ]
        }

    # =========================================
    # Gambling Detection
    # =========================================
    gambling_keywords = [
        "casino",
        "bet",
        "betting",
        "gambling",
        "poker",
        "roulette",
        "slot",
        "jackpot",
        "blackjack",
        "lottery",
        "stake",
        "1xbet",
        "dafabet",
        "parimatch"
    ]

    if any(keyword in url for keyword in gambling_keywords):
        return {
            "url": url,
            "status": "suspicious",
            "risk_score": 85,
            "signals": [
                "Gambling-related website detected",
                "May contain betting or casino content",
                "Proceed carefully"
            ]
        }

    # =========================================
    # Malware / Pirated APK Detection
    # =========================================
    malware_keywords = [
        "crack",
        "modapk",
        "hack",
        "keygen",
        "torrent",
        "warez",
        "pirated",
        "cheat",
        "freeapk",
        "apkmod",
        "malware",
        "virusdownload"
        "happymod"
        "an1"
    ]

    if any(keyword in url for keyword in malware_keywords):
        return {
            "url": url,
            "status": "dangerous",
            "risk_score": 92,
            "signals": [
                "Potential malware or pirated content detected",
                "Website may distribute unsafe files",
                "Downloading from this source is risky"
            ]
        }

    # =========================================
    # AI Phishing Detection
    # =========================================
    features = [extract_features(url)]

    prediction = int(model.predict(features)[0])

    probabilities = model.predict_proba(features)[0]
    classes = list(model.classes_)

    if 1 in classes:
        phishing_index = classes.index(1)
        phishing_probability = float(probabilities[phishing_index])
    else:
        phishing_probability = 0.0

    risk_score = round(phishing_probability * 100)

    # =========================================
    # Final Result
    # =========================================
    if prediction == 0:
        status = "safe"
        signals = [
            "No strong phishing indicators detected",
            "Domain structure appears normal",
            "URL passed AI security analysis"
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

    return {
        "url": url,
        "status": status,
        "risk_score": risk_score,
        "signals": signals
    }