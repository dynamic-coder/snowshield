import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from feature_extractor import extract_features


# Load dataset
# The CSV must contain two columns:
# url,label
# https://google.com,0
# http://paypa1-login.xyz,1

df = pd.read_csv('urls.csv')

# Normalize column names
columns = {c.lower(): c for c in df.columns}

if 'url' not in columns or 'label' not in columns:
    raise ValueError(
        'urls.csv must contain columns named url and label.'\
        '\nExample:'\
        '\nurl,label'\
        '\nhttps://google.com,0'\
        '\nhttp://paypa1-login.xyz,1'
    )

url_col = columns['url']
label_col = columns['label']

# Extract features
X = df[url_col].astype(str).apply(extract_features).tolist()
y = df[label_col]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# Evaluate
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"Model accuracy: {accuracy * 100:.2f}%")

# Save model
joblib.dump(model, 'model.pkl')
print('Model saved as model.pkl')