
(function () {
  'use strict';



  const DETECTION_RULES = [


    {
      type: "Private Key",
      category: "Cryptographic",
      baseScore: 95,
      regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/
    },


    {
      type: "AWS Access Key",
      category: "Cloud Credentials",
      baseScore: 85,
      regex: /\b(?:AKIA|ASIA|AROA|AIPA|ANPA|APKA|AIZA)[A-Z0-9]{16}\b/
    },
    {
      type: "Stripe API Key",
      category: "Cloud Credentials",
      baseScore: 90,
      regex: /\b(?:sk_live_|sk_test_|pk_live_|pk_test_|rk_live_)[a-zA-Z0-9]{20,60}\b/
    },
    {
      type: "GitHub Token",
      category: "Cloud Credentials",
      baseScore: 88,
      regex: /\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,40}\b/
    },
    {
      type: "Slack Token",
      category: "Cloud Credentials",
      baseScore: 82,
      regex: /\bxox[bpase]-[a-zA-Z0-9\-]{10,100}\b/
    },
    {
      type: "SendGrid API Key",
      category: "Cloud Credentials",
      baseScore: 88,
      regex: /\bSG\.[a-zA-Z0-9_\-]{22,60}\.[a-zA-Z0-9_\-]{43,}\b/
    },
    {
      type: "Twilio Account SID",
      category: "Cloud Credentials",
      baseScore: 75,
      regex: /\bAC[a-fA-F0-9]{32}\b/
    },
    {
      type: "JWT Token",
      category: "Cloud Credentials",
      baseScore: 72,
      regex: /\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}/
    },
    {
      type: "Bearer Token",
      category: "Cloud Credentials",
      baseScore: 68,
      regex: /\bBearer\s+[a-zA-Z0-9_\-+\/=]{20,}/i
    },
    {
      type: "API Key (context-anchored)",
      category: "Cloud Credentials",
      baseScore: 72,
      regex: /(?:api[_\-]?key|api[_\-]?secret|access[_\-]?key|auth[_\-]?token|client[_\-]?secret|app[_\-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9_\-+\/=]{12,})["']?/i
    },


    {
      type: "Database Connection String",
      category: "Database Credentials",
      baseScore: 92,
      regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|sqlserver|mariadb|oracle|cockroachdb):\/\/[^\s"'\n]{1,64}:[^\s"'\n@]{1,128}@[^\s"'\n]{4,}/i
    },
    {
      type: "JDBC Connection String",
      category: "Database Credentials",
      baseScore: 88,
      regex: /\bjdbc:(?:postgresql|mysql|oracle|sqlserver|mariadb):\/\/[^\s"'\n]+/i
    },
    {
      type: "Database Password Variable",
      category: "Database Credentials",
      baseScore: 80,
      regex: /\b(?:DB_PASS(?:WORD)?|DATABASE_PASS(?:WORD)?|POSTGRES_PASS(?:WORD)?|MYSQL_PASS(?:WORD)?|MONGO(?:DB)?_PASS(?:WORD)?|REDIS_(?:PASS(?:WORD)?|AUTH)|SQL_PASS(?:WORD)?)\s*[=:]\s*["']?[^\s"'\n]{6,}["']?/i
    },
    {
      type: "DATABASE_URL",
      category: "Database Credentials",
      baseScore: 85,
      regex: /\bDATABASE_URL\s*=\s*["']?[a-z+]+:\/\/[^\s"'\n]{10,}/i
    },


    {
      type: "Password Assignment",
      category: "Credentials",
      baseScore: 78,
      regex: /(?:^|[\s,;{(\n\r])(?:password|passwd|pwd|pass)\s*[:=]\s*["']?([a-zA-Z0-9_\-+\/=@#$%^&*!]{5,})["']?/i
    },
    {
      type: "Username + Password Pair",
      category: "Credentials",
      baseScore: 85,
      regex: /(?:username|user(?:name)?|login|uid)\s*[:=]\s*["']?[^\s"'\n\r,]{3,60}["']?[\s\S]{0,500}?(?:password|passwd|pwd|pass)\s*[:=]\s*["']?([a-zA-Z0-9_\-+\/=@#$%^&*!]{5,})["']?/i
    },
    {
      type: "HTTP Basic Auth Header",
      category: "Credentials",
      baseScore: 88,
      regex: /\bAuthorization\s*:\s*Basic\s+[a-zA-Z0-9+\/=]{8,}/i
    },
    {
      type: "Credentials in URL",
      category: "Credentials",
      baseScore: 88,
      regex: /https?:\/\/[^:@\s"'\n\r]{1,64}:[^@\s"'\n\r]{1,128}@[a-zA-Z0-9.\-]{4,}/i
    },


    {
      type: "Social Security Number",
      category: "PII",
      baseScore: 88,
      regex: /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/
    },
    {
      type: "Credit Card Number",
      category: "Financial",
      baseScore: 82,
      regex: /\b(?:4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}|5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}|3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}|6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4})\b/
    },
    {
      type: "Phone Number",
      category: "PII",
      baseScore: 20,
      regex: /(?:\+?1[-.\s]?)?\(?[2-9][0-9]{2}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/
    },
    {
      type: "Email Address",
      category: "PII",
      baseScore: 15,
      regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/
    },


    {
      type: "Generic Secret Variable",
      category: "Environment Secrets",
      baseScore: 68,
      regex: /\b[A-Z][A-Z0-9_]*_(?:SECRET|TOKEN|AUTH|CREDENTIAL|SIGNING_KEY|ENCRYPTION_KEY|MASTER_KEY|PRIVATE_KEY)\s*=\s*["']?[a-zA-Z0-9_\-+\/=.@#$%^&*!]{12,}["']?/m
    },
    {
      type: "Secret Assignment",
      category: "Environment Secrets",
      baseScore: 65,
      regex: /(?:^|[\s,;{(\n\r])(?:secret|signing_?key|encryption_?key|master_?key|private_?key)\s*[:=]\s*["'][^"'\n\r]{8,}["']/im
    },
  ];



  const REDACTION_PLACEHOLDERS = {
    "Private Key":                 "[PRIVATE_KEY_REDACTED]",
    "AWS Access Key":              "[AWS_KEY_REDACTED]",
    "Stripe API Key":              "[STRIPE_KEY_REDACTED]",
    "GitHub Token":                "[GITHUB_TOKEN_REDACTED]",
    "Slack Token":                 "[SLACK_TOKEN_REDACTED]",
    "SendGrid API Key":            "[SENDGRID_KEY_REDACTED]",
    "Twilio Account SID":          "[TWILIO_SID_REDACTED]",
    "JWT Token":                   "[JWT_TOKEN_REDACTED]",
    "Bearer Token":                "[BEARER_TOKEN_REDACTED]",
    "API Key (context-anchored)":  "[API_KEY_REDACTED]",
    "Database Connection String":  "[DB_CONN_STRING_REDACTED]",
    "JDBC Connection String":      "[JDBC_URL_REDACTED]",
    "Database Password Variable":  "[DB_PASSWORD_REDACTED]",
    "DATABASE_URL":                "[DATABASE_URL_REDACTED]",
    "Password Assignment":         "[PASSWORD_REDACTED]",
    "Username + Password Pair":    "[CREDENTIALS_REDACTED]",
    "HTTP Basic Auth Header":      "[BASIC_AUTH_REDACTED]",
    "Credentials in URL":          "[URL_CREDENTIALS_REDACTED]",
    "Social Security Number":      "[SSN_REDACTED]",
    "Credit Card Number":          "[CREDIT_CARD_REDACTED]",
    "Phone Number":                "[PHONE_REDACTED]",
    "Email Address":               "[EMAIL_REDACTED]",
    "Generic Secret Variable":     "[SECRET_VAR_REDACTED]",
    "Secret Assignment":           "[SECRET_REDACTED]",
  };



  const INTENT_RULES = [
    {
      category: "rewrite_or_modify",
      risk_modifier: 1.4,
      keywords: [
        "keep the api key", "keep as is", "don't change the credentials",
        "leave the secret", "rewrite this and keep",
        "keep it as is", "keep it the same", "don't remove the",
        "leave the api key", "leave the credentials", "keep the credentials", "preserve the key"
      ]
    },
    {
      category: "remove_or_clean",
      risk_modifier: 0.5,
      keywords: [
        "remove the secret", "redact this", "clean this up before i share",
        "strip out the credentials",
        "take out the secret", "get rid of the credentials", "sanitize this",
        "remove sensitive", "before i post this", "before sharing"
      ]
    },
    {
      category: "explain",
      risk_modifier: 0.6,
      keywords: [
        "explain this", "what does this do", "help me understand", "walk me through",
        "can you explain", "please explain", "explain to me", "not sure what this does",
        "what is this doing", "can you break this down", "help me with this"
      ]
    },
    {
      category: "summarize",
      risk_modifier: 0.8,
      keywords: [
        "summarize this", "tldr", "give me a summary",
        "can you summarize", "give me the gist", "short summary", "quick summary"
      ]
    }
  ];



  // ── ML Model Initialization ───────────────────────────────────────────────
  let ML_MODEL = null;
  async function loadMLModel() {
    try {
      const url = chrome.runtime.getURL('model_weights.json');
      const response = await fetch(url);
      ML_MODEL = await response.json();
      ML_MODEL.stopWordsSet = new Set(ML_MODEL.stop_words);
    } catch (e) {
      // Fail silently
    }
  }
  loadMLModel();

  function predictSensitiveML(text) {
    if (!ML_MODEL || !text) return { isSensitive: false, probability: 0, indicatorTerms: [] };

    const lowercaseText = text.toLowerCase();
    const words = [];
    const regex = /[a-zA-Z0-9_]{2,}/g;
    let match;
    while ((match = regex.exec(lowercaseText)) !== null) {
      words.push(match[0]);
    }

    if (words.length === 0) return { isSensitive: false, probability: 0, indicatorTerms: [] };

    const filteredWords = words.filter(w => !ML_MODEL.stopWordsSet.has(w));
    if (filteredWords.length === 0) return { isSensitive: false, probability: 0, indicatorTerms: [] };

    const counts = {};
    for (const word of filteredWords) {
      counts[word] = (counts[word] || 0) + 1;
    }
    for (let i = 0; i < filteredWords.length - 1; i++) {
      const bigram = filteredWords[i] + ' ' + filteredWords[i+1];
      counts[bigram] = (counts[bigram] || 0) + 1;
    }

    let sumSq = 0;
    const activeFeatures = [];
    for (const term in counts) {
      if (term in ML_MODEL.vocabulary) {
        const idx = ML_MODEL.vocabulary[term];
        const idf = ML_MODEL.idf[idx];
        const val = counts[term] * idf;
        activeFeatures.push({ idx, val, term });
        sumSq += val * val;
      }
    }

    if (activeFeatures.length === 0) {
      const prob = 1 / (1 + Math.exp(-ML_MODEL.intercept));
      return { isSensitive: prob >= 0.5, probability: prob, indicatorTerms: [] };
    }

    const norm = Math.sqrt(sumSq);
    let logit = ML_MODEL.intercept;
    const indicatorTerms = [];

    for (const feat of activeFeatures) {
      const normalizedVal = feat.val / norm;
      const termCoef = ML_MODEL.coef[feat.idx];
      logit += normalizedVal * termCoef;

      if (termCoef > 0.4) {
        indicatorTerms.push(feat.term);
      }
    }

    const probability = 1 / (1 + Math.exp(-logit));
    return {
      isSensitive: probability >= 0.5,
      probability: probability,
      indicatorTerms: [...new Set(indicatorTerms)]
    };
  }

  function detectInText(text) {
    if (!text) return [];
    return DETECTION_RULES.filter(rule => {
      rule.regex.lastIndex = 0;
      return rule.regex.test(text);
    });
  }

  function getShannonEntropy(str) {
    const len = str.length;
    if (len === 0) return 0;
    const counts = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      counts[char] = (counts[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in counts) {
      const p = counts[char] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  function isComplexToken(token) {
    const hasLower = /[a-z]/.test(token);
    const hasUpper = /[A-Z]/.test(token);
    const hasDigit = /[0-9]/.test(token);
    return (hasLower && hasUpper && hasDigit) || token.length >= 32;
  }

  function detectGeneralizedSecrets(text) {
    if (!text) return [];
    const matched = [];

    const assignRegex = /\b([a-zA-Z0-9_]{2,60})\s*[:=]\s*["']?([a-zA-Z0-9_\-+\/=!@#$%^&*()]{6,128})["']?/g;
    let match;
    const sensitiveNamePattern = /(?:pass|key|secret|token|auth|cred|sid|pwd|secr)/i;

    while ((match = assignRegex.exec(text)) !== null) {
      const varName = match[1];
      const varValue = match[2];
      
      if (/^(class|id|type|href|src|rel|style|width|height)$/i.test(varName)) continue;
      if (/^\[[A-Z0-9_]+_REDACTED\]$/.test(varValue) || varValue === '[REDACTED]') continue;

      const nameMatches = sensitiveNamePattern.test(varName);
      const entropy = getShannonEntropy(varValue);

      if (nameMatches) {
        if (varValue.length >= 6 && entropy >= 2.5) {
          matched.push({
            type: `Credential Assignment (${varName})`,
            category: "Generalized Secrets",
            baseScore: 80,
            regex: new RegExp(varName + '\\s*[:=]\\s*["\']?' + varValue.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&') + '["\']?', 'i')
          });
        }
      } else {
        if (varValue.length >= 16 && entropy >= 4.2) {
          if (isComplexToken(varValue)) {
            matched.push({
              type: `High-Entropy Variable Value`,
              category: "Generalized Secrets",
              baseScore: 75,
              regex: new RegExp(varName + '\\s*[:=]\\s*["\']?' + varValue.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&') + '["\']?', 'i')
            });
          }
        }
      }
    }

    const tokenRegex = /\b([a-zA-Z0-9_\-+\/=]{16,128})\b/g;
    while ((match = tokenRegex.exec(text)) !== null) {
      const token = match[1];
      if (/^(http|https|contenteditable|authorization|x-request-id|content-type)$/i.test(token)) continue;

      const entropy = getShannonEntropy(token);
      if (token.length >= 16 && entropy >= 4.5) {
        if (isComplexToken(token)) {
          matched.push({
            type: "High-Entropy Token",
            category: "Generalized Secrets",
            baseScore: 70,
            regex: new RegExp('\\b' + token.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&') + '\\b', 'g')
          });
        }
      }
    }

    const unique = [];
    const seen = new Set();
    for (const item of matched) {
      const key = item.type + ":" + item.regex.source;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(item);
      }
    }
    return unique;
  }

  function detectInTextAll(text) {
    if (!text || _redactBypassed) return [];
    
    const matched = detectInText(text);

    const genSecrets = detectGeneralizedSecrets(text);
    matched.push(...genSecrets);

    const mlResult = predictSensitiveML(text);
    if (mlResult.isSensitive) {
      matched.push({
        type: "Semantic Data Leak",
        category: "Machine Learning Analysis",
        baseScore: mlResult.probability >= 0.70 ? 85 : 55
      });
    }

    return matched;
  }

  function detectIntent(text) {
    if (!text) return { intent_category: "unknown", risk_modifier: 1.0, matched_keywords: [] };
    const lower = text.toLowerCase();
    const negationPattern = /\b(don't|dont|not|never|no|avoid|do not)\b/;

    for (const rule of INTENT_RULES) {
      const matched = [];
      for (const kw of rule.keywords) {
        let startIdx = 0;
        while (true) {
          const idx = lower.indexOf(kw, startIdx);
          if (idx === -1) break;

          const prefix = lower.substring(Math.max(0, idx - 15), idx).trim();
          if (!negationPattern.test(prefix)) {
            matched.push(kw);
            break;
          }
          startIdx = idx + 1;
        }
      }
      if (matched.length > 0) {
        return { intent_category: rule.category, risk_modifier: rule.risk_modifier, matched_keywords: matched };
      }
    }
    return { intent_category: "unknown", risk_modifier: 1.0, matched_keywords: [] };
  }

  function computeRiskScore(matchedRules, intentResult) {
    if (!matchedRules || matchedRules.length === 0) {
      return { score: 0, matchedTypes: [], categories: [], intentCategory: 'unknown' };
    }
    const maxBase = Math.max(...matchedRules.map(r => r.baseScore));
    const bonus   = (matchedRules.length - 1) * 8;
    const base    = Math.min(100, maxBase + bonus);
    const mod     = intentResult ? intentResult.risk_modifier : 1.0;
    const score   = Math.min(100, Math.max(0, base * mod));
    return {
      score,
      matchedTypes: matchedRules.map(r => r.type),
      categories:   [...new Set(matchedRules.map(r => r.category))],
      intentCategory: intentResult ? intentResult.intent_category : 'unknown'
    };
  }

  function getRiskLevel(score) {
    if (score < 30)  return "allow";
    if (score < 70)  return "warn";
    return "block";
  }

  function logDetectionEvent(riskData, riskLevel) {
    if (riskLevel === "allow") return;
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;
    chrome.storage.local.get(['detectionLog'], (result) => {
      let log = result.detectionLog || [];
      log.push({
        timestamp:     Date.now(),
        score:         riskData.score,
        matchedTypes:  riskData.matchedTypes,
        categories:    riskData.categories || [],
        intentCategory:riskData.intentCategory,
        riskLevel
      });
      if (log.length > 200) log = log.slice(log.length - 200);
      chrome.storage.local.set({ detectionLog: log });
    });
  }



  function performRedaction(text, matchedRules) {
    let result = text;
    const rulesToUse = matchedRules || detectInTextAll(text);

    for (const rule of rulesToUse) {
      if (rule.category === "Machine Learning Analysis") continue;
      
      const placeholder = REDACTION_PLACEHOLDERS[rule.type] || '[REDACTED]';
      const flags = rule.regex ? (rule.regex.flags.replace('g', '') + 'g') : 'g';
      const gRegex = rule.regex ? new RegExp(rule.regex.source, flags) : null;
      if (gRegex) {
        result = result.replace(gRegex, placeholder);
      }
    }

    const mlResult = predictSensitiveML(result);
    if (mlResult.isSensitive && mlResult.indicatorTerms && mlResult.indicatorTerms.length > 0) {
      for (const term of mlResult.indicatorTerms) {
        const escaped = term.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
        const termRegex = new RegExp('\\b' + escaped + '\\b', 'gi');
        result = result.replace(termRegex, '[REDACTED]');
      }
    }
    return result;
  }




  function getInputArea() {
    const byId = document.getElementById('prompt-textarea');
    if (byId) return byId;

    const selectors = [
      'div[contenteditable="true"][data-lexical-editor]',
      'div[contenteditable="true"].ProseMirror',
      'div[contenteditable="true"][role="textbox"]',
      'div[contenteditable="true"][aria-label*="essage"]',
      'div[contenteditable="true"][aria-label*="rompt"]',
      'div[contenteditable="true"][aria-placeholder]',
      'textarea[placeholder*="essage"]',
      'textarea[aria-label*="essage"]',
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el) return el;
    }
    return null;
  }

  function getSendButton() {
    const selectors = [
      'button[data-testid="send-button"]',
      'button[aria-label*="Send"]',
      'button[aria-label*="send"]',
      'button[data-testid*="send"]',
      'button[title*="Send"]',
      'button[type="submit"]',
    ];
    for (const sel of selectors) {
      const btn = document.querySelector(sel);
      if (btn) return btn;
    }
    return null;
  }

  function getInputText(el) {
    if (!el) return '';
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') return el.value || '';
    if (el.isContentEditable) return el.innerText || el.textContent || '';
    return '';
  }

  function setInputText(el, text) {
    if (!el) return;
    el.focus();
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') {
      const proto = el.tagName === 'TEXTAREA'
        ? window.HTMLTextAreaElement.prototype
        : window.HTMLInputElement.prototype;
      const nativeSetter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (nativeSetter) nativeSetter.call(el, text);
      else el.value = text;
      el.dispatchEvent(new Event('input',  { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    } else if (el.isContentEditable) {
      try {
        el.focus();
        document.execCommand('selectAll', false, null);
      } catch (err) {}

      const htmlText = text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\n/g, '<br>');

      const success = document.execCommand('insertHTML', false, htmlText);
      
      if (!success) {
        document.execCommand('insertText', false, text);
      }
      
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }



  function dismissBanner(banner) {
    if (!banner) return;
    if (banner._dismissTimer) { clearTimeout(banner._dismissTimer); banner._dismissTimer = null; }
    banner.classList.remove('banner-visible');
    setTimeout(() => { if (banner.parentNode) banner.parentNode.removeChild(banner); }, 380);
  }

  function showWarningBanner(matchedRules, intentResult, riskData, riskLevel) {
    let banner = document.getElementById('pasteguard-warning-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'pasteguard-warning-banner';
      document.body.appendChild(banner);
    }
    if (banner._dismissTimer) { clearTimeout(banner._dismissTimer); banner._dismissTimer = null; }

    banner.className = 'pasteguard-warning-banner ' +
      (riskLevel === 'block' ? 'banner-block' : 'banner-warn');

    const score      = riskData.score.toFixed(0);
    const statusText = riskLevel === 'block' ? '🚫 BLOCKED' : '⚠️ WARNING';
    const categories = (riskData.categories || []).join(' · ') || 'Sensitive Data';
    const types      = matchedRules.map(r => r.type).join(', ');
    let intentNote   = '';
    if (intentResult && intentResult.intent_category !== 'unknown') {
      const mod = intentResult.risk_modifier > 1 ? '▲ elevated' : '▼ reduced';
      intentNote = `  |  Intent: ${intentResult.intent_category} (${mod} risk)`;
    }

    const msgSpan = document.createElement('span');
    msgSpan.className = 'pasteguard-msg';
    msgSpan.textContent =
      `PasteGuard ${statusText}  —  Score: ${score}/100  |  ${categories}: ${types}${intentNote}`;

    const closeBtn = document.createElement('button');
    closeBtn.className = 'pasteguard-close-btn';
    closeBtn.textContent = '×';
    closeBtn.title = 'Dismiss';
    closeBtn.addEventListener('click', (e) => { e.stopPropagation(); dismissBanner(banner); });

    banner.innerHTML = '';
    banner.appendChild(msgSpan);
    banner.appendChild(closeBtn);

    requestAnimationFrame(() => requestAnimationFrame(() => { banner.classList.add('banner-visible'); }));

    if (riskLevel === 'warn') {
      banner._dismissTimer = setTimeout(() => dismissBanner(banner), 8000);
    }
  }

  function handlePaste(event) {
    _redactBypassed = false; // Reset bypass flag on new paste to force evaluation
    const clipboardData = event.clipboardData || window.clipboardData;
    if (!clipboardData) return;
    const pastedText = clipboardData.getData('text');
    if (!pastedText) return;

    const matchedRules = detectInTextAll(pastedText);
    if (matchedRules.length === 0) return;

    let accompanyingText = '';
    const el = document.activeElement;
    if (el) {
      if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') accompanyingText = el.value || '';
      else if (el.isContentEditable) accompanyingText = el.textContent || '';
    }

    const intentResult = detectIntent((accompanyingText + ' ' + pastedText).trim());
    const riskData     = computeRiskScore(matchedRules, intentResult);
    const riskLevel    = getRiskLevel(riskData.score);

    logDetectionEvent(riskData, riskLevel);

    if (riskLevel === 'block') event.preventDefault();
    if (riskLevel !== 'allow') showWarningBanner(matchedRules, intentResult, riskData, riskLevel);
  }



  let _sendLocked = false;
  let _redactBypassed = false;
  let _redactedTextLength = 0;

  function lockSend() {
    if (_sendLocked) return;
    _sendLocked = true;
    const btn = getSendButton();
    if (btn) btn.classList.add('pasteguard-send-locked');
  }

  function unlockSend() {
    _sendLocked = false;
    document.querySelectorAll('.pasteguard-send-locked').forEach(el =>
      el.classList.remove('pasteguard-send-locked'));
  }



  function hideRedactToolbar() {
    const el = document.getElementById('pasteguard-redact-toolbar');
    if (!el) return;
    el.classList.remove('toolbar-visible');
    setTimeout(() => { if (el.parentNode) el.parentNode.removeChild(el); }, 350);
  }

  function showRedactToolbar(matchedRules, inputEl) {
    hideRedactToolbar();

    const toolbar = document.createElement('div');
    toolbar.id    = 'pasteguard-redact-toolbar';
    toolbar.className = 'pasteguard-redact-toolbar';

    const header = document.createElement('div');
    header.className = 'pgt-toolbar-header';

    const headerLeft = document.createElement('div');
    headerLeft.className = 'pgt-toolbar-header-left';
    const iconSpan = document.createElement('span');
    iconSpan.className   = 'pgt-toolbar-icon';
    iconSpan.textContent = '🔒';
    headerLeft.appendChild(iconSpan);

    const titleWrap = document.createElement('div');
    const titleEl   = document.createElement('div');
    titleEl.className   = 'pgt-toolbar-title';
    titleEl.textContent = 'Sending blocked — sensitive data detected';
    const subtitleEl    = document.createElement('div');
    subtitleEl.className   = 'pgt-toolbar-subtitle';
    subtitleEl.textContent = 'Redact the secrets below to enable sending.';
    titleWrap.appendChild(titleEl);
    titleWrap.appendChild(subtitleEl);

    const closeBtnX = document.createElement('button');
    closeBtnX.className   = 'pgt-toolbar-close';
    closeBtnX.textContent = '×';
    closeBtnX.title = 'Cancel';
    closeBtnX.addEventListener('click', hideRedactToolbar);

    headerLeft.appendChild(titleWrap);
    header.appendChild(headerLeft);
    header.appendChild(closeBtnX);

    const typesWrap = document.createElement('div');
    typesWrap.className = 'pgt-toolbar-types';

    const grouped = {};
    matchedRules.forEach(r => {
      if (!grouped[r.category]) grouped[r.category] = [];
      grouped[r.category].push(r.type);
    });

    Object.entries(grouped).forEach(([cat, types]) => {
      const row = document.createElement('div');
      row.className = 'pgt-type-row';
      const catLabel = document.createElement('span');
      catLabel.className   = 'pgt-category-label';
      catLabel.textContent = cat + ':';
      row.appendChild(catLabel);
      types.forEach(t => {
        const pill = document.createElement('span');
        pill.className   = 'pgt-type-pill';
        pill.textContent = t;
        row.appendChild(pill);
      });
      typesWrap.appendChild(row);
    });

    const actions = document.createElement('div');
    actions.className = 'pgt-toolbar-actions';

    const redactBtn = document.createElement('button');
    redactBtn.className = 'pgt-btn pgt-btn-primary';
    redactBtn.innerHTML = '🔧&nbsp;&nbsp;Auto-Redact &amp; Enable Send';
    redactBtn.addEventListener('click', () => {
      const currentText  = getInputText(inputEl);
      const redactedText = performRedaction(currentText, matchedRules);

      setInputText(inputEl, redactedText);
      _redactBypassed = true;
      _redactedTextLength = redactedText.length;

      setTimeout(() => {
        hideRedactToolbar();
        unlockSend();
        showSuccessToast('✓ Secrets redacted — you can now send your message.');
        if (inputEl) inputEl.focus();
      }, 120);
    });

    const cancelBtn = document.createElement('button');
    cancelBtn.className   = 'pgt-btn pgt-btn-secondary';
    cancelBtn.textContent = '✕  Cancel';
    cancelBtn.addEventListener('click', hideRedactToolbar);

    actions.appendChild(redactBtn);
    actions.appendChild(cancelBtn);

    toolbar.appendChild(header);
    toolbar.appendChild(typesWrap);
    toolbar.appendChild(actions);
    document.body.appendChild(toolbar);

    requestAnimationFrame(() => requestAnimationFrame(() =>
      toolbar.classList.add('toolbar-visible')
    ));
  }

  function showSuccessToast(message) {
    const existing = document.getElementById('pasteguard-toast');
    if (existing) existing.parentNode.removeChild(existing);

    const toast = document.createElement('div');
    toast.id          = 'pasteguard-toast';
    toast.className   = 'pasteguard-toast';
    toast.textContent = message;
    document.body.appendChild(toast);

    requestAnimationFrame(() => requestAnimationFrame(() =>
      toast.classList.add('toast-visible')
    ));

    setTimeout(() => {
      toast.classList.remove('toast-visible');
      setTimeout(() => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 380);
    }, 3500);
  }



  let _scanTimer   = null;
  let _observedEl  = null;
  let _inputObs    = null;

  function scanCurrentInput() {
    const inputEl = getInputArea();
    if (!inputEl) return;

    const text = getInputText(inputEl);
    if (!text || !text.trim()) {
      _redactBypassed = false;
      unlockSend();
      return;
    }

    if (_redactBypassed && text.length > _redactedTextLength + 5) {
      _redactBypassed = false;
    }

    const matched = detectInTextAll(text);
    if (matched.length === 0) { unlockSend(); return; }

    const riskData = computeRiskScore(matched, null);
    const level    = getRiskLevel(riskData.score);

    if (level === 'allow') unlockSend();
    else                   lockSend();
  }

  function debouncedScan() {
    clearTimeout(_scanTimer);
    _scanTimer = setTimeout(scanCurrentInput, 450);
  }

  function watchInputArea() {
    const inputEl = getInputArea();
    if (!inputEl || inputEl === _observedEl) return;

    if (_inputObs) _inputObs.disconnect();
    _observedEl = inputEl;
    _inputObs   = new MutationObserver(debouncedScan);
    _inputObs.observe(inputEl, { childList: true, subtree: true, characterData: true });

    inputEl.addEventListener('input', debouncedScan);

    debouncedScan();
  }

  setInterval(watchInputArea, 1200);



  function interceptSend(event) {
    let isSendAction = false;

    if (event.type === 'click') {
      const sendBtn = getSendButton();
      if (sendBtn && (sendBtn === event.target || sendBtn.contains(event.target))) {
        isSendAction = true;
      }
    } else if (event.type === 'keydown') {
      if (event.key === 'Enter' && !event.shiftKey) {
        const inputEl = getInputArea();
        if (inputEl && (inputEl === event.target || inputEl.contains(event.target))) {
          isSendAction = true;
        }
      }
    }

    if (!isSendAction) return;

    const inputEl = getInputArea();
    if (!inputEl) return;

    const text    = getInputText(inputEl);
    if (!text || !text.trim()) return;

    const matched  = detectInTextAll(text);
    if (matched.length === 0) return;

    const riskData = computeRiskScore(matched, null);
    const level    = getRiskLevel(riskData.score);
    if (level === 'allow') return;

    event.preventDefault();
    event.stopImmediatePropagation();

    logDetectionEvent(riskData, level);

    showRedactToolbar(matched, inputEl);
  }

  document.addEventListener('paste',   handlePaste,   true);
  document.addEventListener('click',   interceptSend, true);
  document.addEventListener('keydown', interceptSend, true);

  watchInputArea();

})();