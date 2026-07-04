import json
import os
import joblib
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def main():
    # Define directories
    data_dir = os.path.dirname(os.path.abspath(__file__))
    train_path = os.path.join(data_dir, "train.json")
    test_path = os.path.join(data_dir, "test.json")

    # Load datasets
    with open(train_path, "r", encoding="utf-8") as f:
        train_data = json.load(f)
    with open(test_path, "r", encoding="utf-8") as f:
        test_data = json.load(f)

    # Extract train features and labels
    train_texts = [item["text"] for item in train_data]
    train_labels = [item["label"] for item in train_data]

    # Extract test features, labels and borderline indicators
    test_texts = [item["text"] for item in test_data]
    test_labels = [item["label"] for item in test_data]
    test_is_borderline = [item["is_borderline"] for item in test_data]

    print("Building classification pipeline...")
    # Build the classification pipeline
    pipeline = Pipeline([
        ('vectorizer', TfidfVectorizer(max_features=5000, ngram_range=(1,2), stop_words='english')),
        ('classifier', LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42))
    ])

    print("Running Stratified 5-Fold Cross Validation on train set...")
    from sklearn.model_selection import StratifiedKFold, cross_validate
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_results = cross_validate(
        pipeline, train_texts, train_labels, cv=cv,
        scoring=['accuracy', 'precision', 'recall', 'f1'],
        n_jobs=-1
    )
    
    cv_acc = float(np.mean(cv_results['test_accuracy']))
    cv_prec = float(np.mean(cv_results['test_precision']))
    cv_rec = float(np.mean(cv_results['test_recall']))
    cv_f1 = float(np.mean(cv_results['test_f1']))
    
    print(f"CV Accuracy:  {cv_acc:.4f}")
    print(f"CV Precision: {cv_prec:.4f}")
    print(f"CV Recall:    {cv_rec:.4f}")
    print(f"CV F1 Score:  {cv_f1:.4f}")

    print("Fitting model on train set...")
    # Fit the pipeline on the train set only
    pipeline.fit(train_texts, train_labels)

    print("Predicting on test set...")
    # Predict on the test set
    test_preds = pipeline.predict(test_texts)

    # Compute overall metrics
    overall_acc = accuracy_score(test_labels, test_preds)
    overall_prec = precision_score(test_labels, test_preds)
    overall_rec = recall_score(test_labels, test_preds)
    overall_f1 = f1_score(test_labels, test_preds)
    overall_cm = confusion_matrix(test_labels, test_preds)

    print("\n================ OVERALL PERFORMANCE ================")
    print(f"Accuracy:  {overall_acc:.4f}")
    print(f"Precision: {overall_prec:.4f}")
    print(f"Recall:    {overall_rec:.4f}")
    print(f"F1 Score:  {overall_f1:.4f}")
    print("\nConfusion Matrix:")
    print(overall_cm)

    # Compute borderline subset metrics
    test_texts_arr = np.array(test_texts)
    test_labels_arr = np.array(test_labels)
    test_preds_arr = np.array(test_preds)
    test_is_borderline_arr = np.array(test_is_borderline)

    borderline_labels = test_labels_arr[test_is_borderline_arr]
    borderline_preds = test_preds_arr[test_is_borderline_arr]

    borderline_prec = precision_score(borderline_labels, borderline_preds)
    borderline_rec = recall_score(borderline_labels, borderline_preds)
    borderline_f1 = f1_score(borderline_labels, borderline_preds)

    print("\n================ Borderline subset performance ================")
    print(f"Precision (Borderline): {borderline_prec:.4f}")
    print(f"Recall (Borderline):    {borderline_rec:.4f}")
    print(f"F1 Score (Borderline):  {borderline_f1:.4f}")

    # Extract model coefficients and feature names
    vectorizer = pipeline.named_steps['vectorizer']
    classifier = pipeline.named_steps['classifier']
    feature_names = vectorizer.get_feature_names_out()
    coefficients = classifier.coef_[0]

    feature_coefficients = list(zip(feature_names, coefficients))

    # Sort coefficients to find top words/n-grams
    top_sensitive = sorted(feature_coefficients, key=lambda x: x[1], reverse=True)[:15]
    top_safe = sorted(feature_coefficients, key=lambda x: x[1], reverse=False)[:15]

    print("\n================ Top 15 Predictive Features (Sensitive - Label 1) ================")
    for word, coef in top_sensitive:
        print(f" - {word:<25} : {coef:.4f}")

    print("\n================ Top 15 Predictive Features (Safe - Label 0) ================")
    for word, coef in top_safe:
        print(f" - {word:<25} : {coef:.4f}")

    # Save trained pipeline
    model_save_path = os.path.join(data_dir, "classifier_model.joblib")
    joblib.dump(pipeline, model_save_path)
    print(f"\nSaved trained model pipeline to {model_save_path}")

    # Save evaluation results to JSON file
    eval_results = {
        "model_version": "v2_current",
        "notes": "Trained with hard negatives and evaluated with Stratified 5-Fold Cross-Validation.",
        "cross_validation": {
            "accuracy": cv_acc,
            "precision": cv_prec,
            "recall": cv_rec,
            "f1_score": cv_f1
        },
        "overall": {
            "accuracy": float(overall_acc),
            "precision": float(overall_prec),
            "recall": float(overall_rec),
            "f1_score": float(overall_f1),
            "confusion_matrix": overall_cm.tolist()
        },
        "borderline": {
            "precision": float(borderline_prec),
            "recall": float(borderline_rec),
            "f1_score": float(borderline_f1)
        }
    }

    eval_save_path = os.path.join(data_dir, "eval_results.json")
    with open(eval_save_path, "w", encoding="utf-8") as f:
        json.dump(eval_results, f, indent=2)
    print(f"Saved evaluation results to {eval_save_path}")

if __name__ == "__main__":
    main()
