import joblib

def main():
    pipeline = joblib.load("data/classifier_model.joblib")
    text = """import os os.system("ls")
//Output .env home.txt
cat .env
USERNAME=admin PASSWORD=sup3rs3cr3tpassw0rd HOST=localhost
AWS_ACCESS_KEY_ID=AIZAOSHWUAI172AA"""
    
    prob = pipeline.predict_proba([text])[0][1]
    pred = pipeline.predict([text])[0]
    print(f"ML Model Probability: {prob:.4f}")
    print(f"ML Model Prediction: {pred}")

if __name__ == "__main__":
    main()
