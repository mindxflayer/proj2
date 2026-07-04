import json
import os
import joblib

def main():
    # Define directories
    data_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(data_dir, "classifier_model.joblib")
    test_path = os.path.join(data_dir, "test.json")

    # Load model and test data
    pipeline = joblib.load(model_path)
    with open(test_path, "r", encoding="utf-8") as f:
        test_data = json.load(f)

    # Extract texts and labels
    test_texts = [item["text"] for item in test_data]
    test_labels = [item["label"] for item in test_data]

    # Predict
    test_preds = pipeline.predict(test_texts)

    false_positives = []
    false_negatives = []

    for item, label, pred in zip(test_data, test_labels, test_preds):
        if label != pred:
            error_record = {
                "id": item["id"],
                "text": item["text"],
                "true_label": label,
                "predicted_label": int(pred),
                "is_borderline": item["is_borderline"]
            }
            if label == 0 and pred == 1:
                false_positives.append(error_record)
            elif label == 1 and pred == 0:
                false_negatives.append(error_record)

    # Print to console
    print("\n================ FALSE POSITIVES (Predicted Sensitive, Actually Safe) ================")
    print(f"Total False Positives: {len(false_positives)}")
    for idx, fp in enumerate(false_positives):
        print(f"\n[{idx+1}] ID: {fp['id']} | Is Borderline: {fp['is_borderline']}")
        print(f"Text:\n{fp['text']}")
        print("-" * 50)

    print("\n================ FALSE NEGATIVES (Predicted Safe, Actually Sensitive) ================")
    print(f"Total False Negatives: {len(false_negatives)}")
    for idx, fn in enumerate(false_negatives):
        print(f"\n[{idx+1}] ID: {fn['id']} | Is Borderline: {fn['is_borderline']}")
        print(f"Text:\n{fn['text']}")
        print("-" * 50)

    # Save to file
    out_path = os.path.join(data_dir, "misclassified_examples.json")
    output_data = {
        "false_positives": false_positives,
        "false_negatives": false_negatives
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"\nSaved misclassifications analysis to {out_path}")

if __name__ == "__main__":
    main()
