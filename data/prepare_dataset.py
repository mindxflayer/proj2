import json
import os
import glob
from sklearn.model_selection import train_test_split
from sklearn.utils import shuffle

def main():
    # Define directory
    data_dir = os.path.dirname(os.path.abspath(__file__))

    # Find matching files: sens_*.json, sensitive_*.json, safe_*.json, and borderline_ambiguous.json
    pattern_sens = glob.glob(os.path.join(data_dir, "sens_*.json")) + glob.glob(os.path.join(data_dir, "sensitive_*.json"))
    pattern_safe = glob.glob(os.path.join(data_dir, "safe_*.json"))
    borderline_file = os.path.join(data_dir, "borderline_ambiguous.json")

    # Combine file lists and uniqueify
    input_files = list(set(pattern_sens + pattern_safe))
    if os.path.exists(borderline_file):
        input_files.append(borderline_file)

    input_files = sorted(list(set(input_files)))

    print("Loading files:")
    for f in input_files:
        print(f" - {os.path.basename(f)}")

    combined_records = []

    for file_path in input_files:
        filename = os.path.basename(file_path)
        is_borderline = (filename == "borderline_ambiguous.json")
        
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        for item in data:
            category = item.get("category", "")
            if category == "clearly_sensitive":
                label = 1
            elif category == "clearly_safe":
                label = 0
            elif category == "borderline":
                true_label = item.get("true_label", "")
                if true_label == "leans_sensitive":
                    label = 1
                elif true_label == "leans_safe":
                    label = 0
                else:
                    raise ValueError(f"Unknown true_label: {true_label} in item {item.get('id')}")
            else:
                raise ValueError(f"Unknown category: {category} in item {item.get('id')}")
                
            record = {
                "id": item["id"],
                "text": item["text"],
                "label": label,
                "is_borderline": is_borderline
            }
            combined_records.append(record)

    print(f"Total loaded records: {len(combined_records)}")

    # Shuffle using a fixed random seed for reproducibility
    combined_records = shuffle(combined_records, random_state=42)

    # Extract labels for stratified sampling
    labels = [r["label"] for r in combined_records]

    # Split into 70% train / 30% test
    train_records, test_records = train_test_split(
        combined_records,
        test_size=0.3,
        random_state=42,
        stratify=labels
    )

    # Save splits
    train_path = os.path.join(data_dir, "train.json")
    test_path = os.path.join(data_dir, "test.json")

    with open(train_path, "w", encoding="utf-8") as f:
        json.dump(train_records, f, indent=2)

    with open(test_path, "w", encoding="utf-8") as f:
        json.dump(test_records, f, indent=2)

    # Print summary statistics
    train_labels = [r["label"] for r in train_records]
    test_labels = [r["label"] for r in test_records]

    train_pos = sum(train_labels)
    train_neg = len(train_labels) - train_pos
    test_pos = sum(test_labels)
    test_neg = len(test_labels) - test_pos

    borderline_in_test = sum(1 for r in test_records if r["is_borderline"])

    print("\n--- Summary ---")
    print(f"Total examples: {len(combined_records)}")
    print(f"Train count: {len(train_records)}")
    print(f"Test count: {len(test_records)}")
    print(f"Train split class balance: Label 1 = {train_pos} ({train_pos/len(train_records):.2%}), Label 0 = {train_neg} ({train_neg/len(train_records):.2%})")
    print(f"Test split class balance:  Label 1 = {test_pos} ({test_pos/len(test_records):.2%}), Label 0 = {test_neg} ({test_neg/len(test_records):.2%})")
    print(f"Borderline examples in test set: {borderline_in_test}")

if __name__ == "__main__":
    main()
