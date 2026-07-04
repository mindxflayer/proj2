import re

# ══════════════════════════════════════════════════════════════════
# IMPORTANT: Keep INTENT_RULES in sync with content.js
# Both files use the same categories, keywords, and risk_modifiers.
# ══════════════════════════════════════════════════════════════════
INTENT_RULES = [
    {
        "category": "rewrite_or_modify",
        "risk_modifier": 1.4,
        "keywords": [
            "keep the api key", "keep as is", "don't change the credentials",
            "leave the secret", "rewrite this and keep",
            "keep it as is", "keep it the same", "don't remove the",
            "leave the api key", "leave the credentials", "keep the credentials", "preserve the key"
        ]
    },
    {
        "category": "remove_or_clean",
        "risk_modifier": 0.5,
        "keywords": [
            "remove the secret", "redact this", "clean this up before i share",
            "strip out the credentials",
            "take out the secret", "get rid of the credentials", "sanitize this",
            "remove sensitive", "before i post this", "before sharing"
        ]
    },
    {
        "category": "explain",
        "risk_modifier": 0.6,
        "keywords": [
            "explain this", "what does this do", "help me understand", "walk me through",
            "can you explain", "please explain", "explain to me", "not sure what this does",
            "what is this doing", "can you break this down", "help me with this"
        ]
    },
    {
        "category": "summarize",
        "risk_modifier": 0.8,
        "keywords": [
            "summarize this", "tldr", "give me a summary",
            "can you summarize", "give me the gist", "short summary", "quick summary"
        ]
    }
]

def detect_intent(accompanying_text: str) -> dict:
    text_lower = accompanying_text.lower()
    negation_pattern = re.compile(r'\b(don\'t|dont|not|never|no|avoid|do not)\b')
    
    # Priority is determined by the order in INTENT_RULES:
    # 1. rewrite_or_modify (highest risk, trumps others because preserving secrets is high risk)
    # 2. remove_or_clean
    # 3. explain
    # 4. summarize
    for rule in INTENT_RULES:
        matched = []
        for kw in rule["keywords"]:
            start_idx = 0
            while True:
                idx = text_lower.find(kw, start_idx)
                if idx == -1:
                    break
                
                # Check for negation in the 15 characters before the match
                prefix = text_lower[max(0, idx - 15):idx].strip()
                if negation_pattern.search(prefix):
                    # Keyword is negated, skip
                    pass
                else:
                    matched.append(kw)
                    break # Stop scanning occurrences for this keyword
                start_idx = idx + 1
        
        if matched:
            return {
                "intent_category": rule["category"],
                "risk_modifier": rule["risk_modifier"],
                "matched_keywords": matched
            }
            
    return {
        "intent_category": "unknown",
        "risk_modifier": 1.0,
        "matched_keywords": []
    }

if __name__ == "__main__":
    test_cases = [
        # Rewrite/Modify signals
        "Please rewrite this and keep the api key inside it.",
        "keep as is so my code continues to work.",
        "don't change the credentials, just format the code.",
        
        # Remove/Clean signals
        "remove the secret from this config.",
        "Can you redact this before I commit?",
        "clean this up before I share it with the team.",
        
        # Explain signals
        "explain this block of code",
        "what does this do exactly?",
        "help me understand how the auth works.",
        
        # Summarize signals
        "summarize this long file",
        "give me a summary of the changes.",
        "tldr please.",
        
        # Mixed signals (Tricky cases)
        # Should be rewrite_or_modify because preserving secrets takes priority over explain
        "explain this and rewrite it but keep the api key.",
        "help me understand this, but don't change the credentials.",
        
        # Should be remove_or_clean (trumps explain)
        "explain this, then remove the secret.",
        
        # Unknown/No clear signal
        "is this secure?",
        "check the syntax on line 42.",
        "Looks good to me.",

        # New test cases
        "can you explain to me what this does",
        "please explain this in simple terms",
        "keep it as is, don't touch the key",
        "sanitize this before I post this",
        "can you give me the gist of this"
    ]
    
    print(f"{'Input Text':<60} | {'Detected Category':<20} | {'Risk':<5} | {'Keywords'}")
    print("-" * 120)
    for text in test_cases:
        res = detect_intent(text)
        print(f"{text[:58]:<60} | {res['intent_category']:<20} | {res['risk_modifier']:<5} | {res['matched_keywords']}")
