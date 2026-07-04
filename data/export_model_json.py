import os
import json
import joblib
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

def main():
    data_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(data_dir, "classifier_model.joblib")
    
    if not os.path.exists(model_path):
        print(f"Model file {model_path} not found. Please run train_classifier.py first.")
        return
        
    pipeline = joblib.load(model_path)
    vectorizer = pipeline.named_steps['vectorizer']
    classifier = pipeline.named_steps['classifier']
    
    # Extract params
    vocabulary = {str(k): int(v) for k, v in vectorizer.vocabulary_.items()}
    idf = vectorizer.idf_.tolist()
    coef = classifier.coef_[0].tolist()
    intercept = float(classifier.intercept_[0])
    
    # Get stop words list
    stop_words = sorted(list(ENGLISH_STOP_WORDS))
    
    model_weights = {
        "vocabulary": vocabulary,
        "idf": idf,
        "coef": coef,
        "intercept": intercept,
        "stop_words": stop_words
    }
    
    # Save to project root (so the extension can load it)
    project_root = os.path.dirname(data_dir)
    weights_path = os.path.join(project_root, "model_weights.json")
    
    with open(weights_path, "w", encoding="utf-8") as f:
        json.dump(model_weights, f, indent=2)
        
    print(f"Successfully exported model weights to {weights_path}")
    print(f"Vocabulary size: {len(vocabulary)}")
    print(f"IDF size: {len(idf)}")
    print(f"Coefficients size: {len(coef)}")
    print(f"Intercept: {intercept:.4f}")
    print(f"Stop words count: {len(stop_words)}")

if __name__ == "__main__":
    main()
