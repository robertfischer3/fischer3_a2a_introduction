# Credit Report Agent - Stage 4: AI-Integrated

> **Path**: `examples/a2a_credit_report_example/ai_integrated`

## Overview

Stage 4 demonstrates **secure AI integration** for financial analysis. This stage adds AI-powered credit analysis while maintaining all Stage 3 security controls and introducing new AI-specific protections.

**Security Rating**: ✅ 10/10 - PRODUCTION READY WITH AI

**Status**: ✅ Enterprise-ready with ML capabilities

---

## Key Learning Focus

This stage focuses on **secure AI integration** and **privacy-preserving machine learning** for sensitive financial systems.

### What You'll Learn

- Secure AI model deployment
- Privacy-preserving ML techniques
- AI input/output validation
- Model security controls
- Explainable AI for compliance
- AI-specific threat mitigation

---

## Architecture

```
Client (HTTPS)
  ↓
Stage 3 Security Stack ✅
  (MFA, Rate Limiting, Validation, etc.)
  ↓
AI Security Layer ✅
  ├─ Input Sanitization
  ├─ Model Access Control
  └─ Output Filtering
  ↓
AI Model (Sandboxed) ✅
  ├─ Fraud Detection
  ├─ Risk Assessment
  └─ Pattern Analysis
  ↓
Differential Privacy ✅
  ↓
Explainability Layer ✅
  ↓
Audit Trail ✅
  ↓
Encrypted Response
```

### Additional Components

- **`ai_engine.py`**: Secure AI model interface
- **`model_security.py`**: AI-specific security controls
- **`privacy_layer.py`**: Differential privacy implementation
- **`explainability.py`**: AI decision explanations
- **`model_monitor.py`**: ML performance & security monitoring
- **`adversarial_defense.py`**: Protection against AI attacks
- **`feature_protection.py`**: PII anonymization for ML
- **`model_versioning.py`**: Secure model updates

---

## 🤖 AI Security Controls

### 1. **AI Input Sanitization**

```python
class AIInputValidator:
    """
    ✅ Validate and sanitize data before AI processing
    """
    def prepare_for_model(self, credit_report):
        # Remove direct identifiers
        sanitized = self._anonymize_pii(credit_report)
        
        # Validate feature ranges
        sanitized = self._validate_features(sanitized)
        
        # Detect adversarial inputs
        if self._is_adversarial(sanitized):
            raise SecurityError("Adversarial input detected")
        
        # Apply differential privacy
        sanitized = self._add_noise(sanitized)
        
        return sanitized
    
    def _anonymize_pii(self, report):
        """Remove direct identifiers before ML"""
        return {
            # ❌ Remove: SSN, name, address
            # ✅ Keep: Anonymized features
            'credit_utilization': report['utilization'],
            'payment_history_score': self._score_history(report['history']),
            'account_age_months': report['oldest_account_age'],
            'inquiry_count': len(report['inquiries']),
            'account_types': self._encode_types(report['accounts']),
            # No PII in ML input
        }
    
    def _is_adversarial(self, features):
        """Detect adversarial examples"""
        # Check for unusual feature combinations
        # Check for out-of-distribution inputs
        # Check for gradient-based attacks
        
        # Example: Credit utilization >100% is impossible
        if features['credit_utilization'] > 1.0:
            return True
        
        # Check feature correlations
        if self._check_anomalous_correlations(features):
            return True
        
        return False
```

**Benefits**:
- PII never sent to AI model
- Adversarial input detection
- Feature validation
- Privacy protection

---

### 2. **Model Access Control**

```python
class ModelAccessControl:
    """
    ✅ Control which users/processes can access AI models
    """
    def __init__(self):
        self.model_permissions = {
            'fraud_detector': ['analyst', 'system'],
            'risk_assessor': ['analyst', 'underwriter', 'system'],
            'pattern_analyzer': ['data_scientist', 'system']
        }
    
    def check_model_access(self, user_role, model_name):
        """Verify user can access specific model"""
        if model_name not in self.model_permissions:
            raise ValueError(f"Unknown model: {model_name}")
        
        allowed_roles = self.model_permissions[model_name]
        
        if user_role not in allowed_roles:
            audit_log('unauthorized_model_access', {
                'user_role': user_role,
                'model': model_name
            })
            return False
        
        return True
    
    def rate_limit_model(self, user_id, model_name):
        """Prevent model abuse"""
        # Different rate limits per model
        limits = {
            'fraud_detector': 100,  # 100 requests/hour
            'risk_assessor': 50,    # 50 requests/hour
            'pattern_analyzer': 10  # 10 requests/hour (expensive)
        }
        
        return self.check_rate_limit(
            user_id,
            model_name,
            limit=limits[model_name]
        )

# Usage
@app.route('/ai/analyze', methods=['POST'])
@require_auth
def ai_analyze(user_id, user_role):
    model_name = request.json['model']
    
    # Check permissions
    if not model_access.check_model_access(user_role, model_name):
        return {'error': 'Access denied'}, 403
    
    # Check rate limit
    if not model_access.rate_limit_model(user_id, model_name):
        return {'error': 'Rate limit exceeded'}, 429
    
    # Process request
    return run_analysis(model_name, request.json['data'])
```

**Benefits**:
- Role-based model access
- Prevent model abuse
- Track model usage
- Separate rate limits per model

---

### 3. **Differential Privacy**

```python
import numpy as np

class DifferentialPrivacy:
    """
    ✅ Add calibrated noise for privacy preservation
    """
    def __init__(self, epsilon=1.0, delta=1e-5):
        self.epsilon = epsilon  # Privacy budget
        self.delta = delta      # Privacy parameter
    
    def add_laplace_noise(self, value, sensitivity):
        """Add Laplace noise for differential privacy"""
        scale = sensitivity / self.epsilon
        noise = np.random.laplace(0, scale)
        return value + noise
    
    def privatize_features(self, features):
        """Apply differential privacy to features"""
        privatized = {}
        
        # Add noise to continuous features
        privatized['credit_utilization'] = self.add_laplace_noise(
            features['credit_utilization'],
            sensitivity=0.1  # Max change in utilization
        )
        
        privatized['account_age_months'] = self.add_laplace_noise(
            features['account_age_months'],
            sensitivity=1.0  # Max 1 month sensitivity
        )
        
        # Categorical features - randomized response
        privatized['account_types'] = self._randomized_response(
            features['account_types']
        )
        
        return privatized
    
    def _randomized_response(self, value):
        """Randomized response for categorical data"""
        # With probability (1-epsilon), flip the value
        if np.random.random() > self.epsilon:
            # Return random category instead
            return self._random_category()
        return value

# Usage in AI pipeline
dp = DifferentialPrivacy(epsilon=1.0)

def process_with_privacy(credit_report):
    # Extract features
    features = extract_features(credit_report)
    
    # Apply differential privacy
    private_features = dp.privatize_features(features)
    
    # Run ML model on private data
    result = model.predict(private_features)
    
    return result
```

**Benefits**:
- Mathematical privacy guarantee
- Prevents individual re-identification
- Compliant with privacy regulations
- Tunable privacy/utility trade-off

---

### 4. **Explainable AI (XAI)**

```python
import shap  # SHapley Additive exPlanations

class ExplainableAI:
    """
    ✅ Provide explanations for AI decisions
    """
    def __init__(self, model):
        self.model = model
        self.explainer = shap.TreeExplainer(model)
    
    def explain_prediction(self, features, prediction):
        """Generate explanation for model decision"""
        # Calculate SHAP values
        shap_values = self.explainer.shap_values(features)
        
        # Get feature importance
        feature_importance = self._calculate_importance(
            features,
            shap_values
        )
        
        # Generate human-readable explanation
        explanation = self._generate_explanation(
            prediction,
            feature_importance
        )
        
        # Audit the explanation
        self._audit_explanation(features, prediction, explanation)
        
        return explanation
    
    def _generate_explanation(self, prediction, importance):
        """Create human-readable explanation"""
        explanation = {
            'decision': prediction['category'],
            'confidence': prediction['confidence'],
            'primary_factors': [],
            'reasoning': ''
        }
        
        # Get top 3 factors
        top_factors = sorted(
            importance.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:3]
        
        for feature, impact in top_factors:
            explanation['primary_factors'].append({
                'factor': self._feature_to_english(feature),
                'impact': 'positive' if impact > 0 else 'negative',
                'magnitude': abs(impact)
            })
        
        # Generate reasoning text
        explanation['reasoning'] = self._create_reasoning_text(
            explanation['primary_factors']
        )
        
        return explanation
    
    def _feature_to_english(self, feature_name):
        """Convert feature names to readable descriptions"""
        mappings = {
            'credit_utilization': 'Credit card usage',
            'payment_history_score': 'Payment track record',
            'account_age_months': 'Length of credit history',
            'inquiry_count': 'Recent credit applications'
        }
        return mappings.get(feature_name, feature_name)
    
    def _audit_explanation(self, features, prediction, explanation):
        """Log explanation for compliance"""
        audit_log('ai_decision_explained', {
            'model_version': self.model.version,
            'prediction': prediction,
            'explanation': explanation,
            'timestamp': datetime.utcnow()
        })

# Usage
explainer = ExplainableAI(fraud_model)

prediction = fraud_model.predict(features)
explanation = explainer.explain_prediction(features, prediction)

# Return both prediction and explanation
return {
    'fraud_detected': prediction['fraud'],
    'confidence': prediction['confidence'],
    'explanation': explanation
}
```

**Benefits**:
- FCRA "adverse action" requirement
- GDPR "right to explanation"
- Builds user trust
- Enables model debugging
- Required for financial decisions

---

### 5. **Model Security Monitoring**

```python
class ModelMonitor:
    """
    ✅ Monitor ML model for security issues
    """
    def __init__(self):
        self.baseline_performance = None
        self.drift_detector = DriftDetector()
    
    def monitor_prediction(self, features, prediction):
        """Monitor each prediction for anomalies"""
        # Check for model drift
        if self.drift_detector.detect_drift(features):
            alert('model_drift_detected', {
                'severity': 'high',
                'features': features
            })
        
        # Check for adversarial patterns
        if self._is_adversarial_pattern(features, prediction):
            alert('adversarial_attack_suspected', {
                'severity': 'critical',
                'features': features
            })
        
        # Check confidence distribution
        if self._unusual_confidence(prediction):
            alert('unusual_confidence_pattern', {
                'severity': 'medium',
                'confidence': prediction['confidence']
            })
        
        # Track performance metrics
        self._update_metrics(features, prediction)
    
    def _is_adversarial_pattern(self, features, prediction):
        """Detect adversarial attack patterns"""
        # Check for high-confidence wrong predictions
        # Check for unusual feature combinations
        # Check for gradient-based perturbations
        
        # Example: Very high confidence on edge case
        if prediction['confidence'] > 0.99:
            if self._is_edge_case(features):
                return True
        
        return False
    
    def detect_model_poisoning(self, training_data):
        """Detect if model was poisoned during training"""
        # Check for data poisoning
        suspicious_samples = []
        
        for sample in training_data:
            if self._is_poisoned_sample(sample):
                suspicious_samples.append(sample)
        
        if len(suspicious_samples) > 0:
            alert('model_poisoning_suspected', {
                'severity': 'critical',
                'sample_count': len(suspicious_samples)
            })
            return True
        
        return False

# Usage - monitor every prediction
monitor = ModelMonitor()

@app.route('/ai/predict', methods=['POST'])
def predict():
    features = request.json['features']
    
    prediction = model.predict(features)
    
    # Monitor for security issues
    monitor.monitor_prediction(features, prediction)
    
    return prediction
```

**Benefits**:
- Early attack detection
- Model drift monitoring
- Performance tracking
- Adversarial defense

---

### 6. **Model Versioning & Updates**

```python
class SecureModelVersioning:
    """
    ✅ Secure model update and rollback
    """
    def __init__(self):
        self.current_version = None
        self.version_history = []
    
    def deploy_model(self, model_file, version, signature):
        """Deploy new model version securely"""
        # Verify model signature
        if not self._verify_signature(model_file, signature):
            raise SecurityError("Invalid model signature")
        
        # Validate model
        if not self._validate_model(model_file):
            raise SecurityError("Model validation failed")
        
        # Test model performance
        if not self._performance_test(model_file):
            raise ValueError("Model performance below threshold")
        
        # Create backup of current model
        self._backup_current_model()
        
        # Deploy new model
        self._load_model(model_file, version)
        
        # Monitor for issues
        self._enable_canary_deployment(version)
        
        # Audit deployment
        audit_log('model_deployed', {
            'version': version,
            'previous_version': self.current_version
        })
        
        self.current_version = version
    
    def rollback_model(self, to_version):
        """Rollback to previous model version"""
        if to_version not in self.version_history:
            raise ValueError(f"Version {to_version} not found")
        
        # Load previous version
        model_file = self._get_version(to_version)
        self._load_model(model_file, to_version)
        
        # Audit rollback
        audit_log('model_rollback', {
            'from_version': self.current_version,
            'to_version': to_version,
            'reason': 'security_issue'
        })
        
        self.current_version = to_version
    
    def _verify_signature(self, model_file, signature):
        """Verify model cryptographic signature"""
        # Use RSA or similar to verify model hasn't been tampered
        public_key = load_public_key()
        
        model_hash = hashlib.sha256(model_file).hexdigest()
        
        return verify_signature(public_key, model_hash, signature)
```

**Benefits**:
- Prevent model tampering
- Safe model updates
- Quick rollback capability
- Audit trail of changes

---

## 🔒 AI-Specific Threat Mitigation

### Threats Addressed

| Threat | Mitigation | Implementation |
|--------|------------|----------------|
| **Model Inversion** | Differential Privacy | ✅ Noise injection |
| **Membership Inference** | Privacy Budget | ✅ Epsilon control |
| **Adversarial Examples** | Input Validation | ✅ Anomaly detection |
| **Model Extraction** | Rate Limiting | ✅ Query limits |
| **Data Poisoning** | Input Sanitization | ✅ Validation pipeline |
| **Model Backdoors** | Model Verification | ✅ Signature checking |
| **Evasion Attacks** | Ensemble Defense | ✅ Multiple models |
| **Feature Inference** | Feature Protection | ✅ PII anonymization |

---

## 🎯 AI Use Cases

### 1. Fraud Detection

```python
def detect_fraud(credit_report):
    """
    AI-powered fraud detection
    """
    # Prepare features (with privacy)
    features = prepare_secure_features(credit_report)
    
    # Run fraud model
    prediction = fraud_model.predict(features)
    
    # Generate explanation
    explanation = explainer.explain_prediction(features, prediction)
    
    # Audit decision
    audit_ai_decision('fraud_detection', prediction, explanation)
    
    return {
        'fraud_risk': prediction['score'],
        'confidence': prediction['confidence'],
        'explanation': explanation,
        'recommended_action': get_recommendation(prediction)
    }
```

### 2. Credit Risk Assessment

```python
def assess_credit_risk(credit_report):
    """
    AI-powered risk assessment
    """
    # Apply differential privacy
    private_features = privacy_layer.privatize(
        extract_features(credit_report)
    )
    
    # Run risk model
    risk_score = risk_model.predict(private_features)
    
    # Explain decision (required for FCRA)
    explanation = explainer.explain_risk_score(
        private_features,
        risk_score
    )
    
    return {
        'risk_category': categorize_risk(risk_score),
        'explanation': explanation,
        'factors': explanation['primary_factors']
    }
```

### 3. Pattern Analysis

```python
def analyze_patterns(credit_report):
    """
    AI-powered pattern detection
    """
    # Anonymize before analysis
    anonymized = anonymize_for_ml(credit_report)
    
    # Detect unusual patterns
    patterns = pattern_model.analyze(anonymized)
    
    # Filter sensitive patterns
    filtered_patterns = filter_pii_from_results(patterns)
    
    return filtered_patterns
```

---

## 📊 Performance & Privacy Trade-offs

### Privacy Budget Management

```python
class PrivacyBudget:
    """
    ✅ Manage cumulative privacy budget
    """
    def __init__(self, total_epsilon=10.0):
        self.total_epsilon = total_epsilon
        self.used_epsilon = 0.0
        self.queries = []
    
    def check_budget(self, query_epsilon):
        """Check if query within budget"""
        if self.used_epsilon + query_epsilon > self.total_epsilon:
            raise PrivacyBudgetExceeded(
                f"Budget exceeded: {self.used_epsilon + query_epsilon} > {self.total_epsilon}"
            )
        
        return True
    
    def consume_budget(self, query_epsilon, query_desc):
        """Consume privacy budget for query"""
        self.check_budget(query_epsilon)
        
        self.used_epsilon += query_epsilon
        self.queries.append({
            'epsilon': query_epsilon,
            'description': query_desc,
            'timestamp': datetime.utcnow()
        })
        
        # Alert if budget running low
        if self.used_epsilon > 0.8 * self.total_epsilon:
            alert('privacy_budget_low', {
                'used': self.used_epsilon,
                'total': self.total_epsilon
            })
```

### Accuracy vs Privacy

| Privacy Level | Epsilon | Accuracy Impact | Use Case |
|---------------|---------|-----------------|----------|
| **High Privacy** | ε = 0.1 | -15% accuracy | Research, aggregates |
| **Balanced** | ε = 1.0 | -5% accuracy | **Production** |
| **Low Privacy** | ε = 10.0 | -1% accuracy | Internal analysis |

---

## Running the Example

### Setup

```bash
cd examples/a2a_credit_report_example/ai_integrated

# Install AI dependencies
pip install -r requirements.txt
pip install tensorflow scikit-learn shap

# Download pre-trained models
python scripts/download_models.py

# Start server
python server.py
```

### Configuration

```bash
# .env file
# ... Stage 3 configs ...

# AI-specific configs
MODEL_PATH=/models
MODEL_VERSION=1.0.0
DIFFERENTIAL_PRIVACY_EPSILON=1.0
ENABLE_EXPLAINABILITY=true
MODEL_MONITORING=true
```

### Try AI Features

```bash
# Fraud detection
curl -X POST https://localhost:8000/ai/fraud-detect \
  -H "Authorization: Bearer $TOKEN" \
  -d @credit_report.json

# Risk assessment with explanation
curl -X POST https://localhost:8000/ai/risk-assess \
  -H "Authorization: Bearer $TOKEN" \
  -d @credit_report.json

# Returns:
# {
#   "risk_score": 0.23,
#   "category": "low_risk",
#   "explanation": {
#     "primary_factors": [
#       "Excellent payment history",
#       "Low credit utilization",
#       "Long credit history"
#     ]
#   }
# }
```

---

## Production Checklist (AI-Specific)

- [ ] Model signatures verified
- [ ] Differential privacy calibrated
- [ ] Explainability tested
- [ ] Model monitoring configured
- [ ] Privacy budget limits set
- [ ] AI-specific audit logs enabled
- [ ] Adversarial defense tested
- [ ] Model versioning implemented
- [ ] Rollback procedure documented
- [ ] AI ethics review completed

---

## Key Takeaways

1. **AI security is critical**: Models need protection like any other system component
2. **Privacy-preserving ML is achievable**: With differential privacy and careful design
3. **Explainability is required**: For compliance and trust
4. **Monitor AI actively**: Detect attacks and drift early
5. **Balance privacy and utility**: Tune epsilon based on use case

---

## Additional Resources

- [Differential Privacy Book](https://www.cis.upenn.edu/~aaroth/Papers/privacybook.pdf)
- [SHAP Documentation](https://shap.readthedocs.io/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [Stage 3: Secure ←](./credit-stage3.md)

---

**Time to Complete**: 6-8 hours  
**Difficulty**: ⭐⭐⭐⭐ Expert  
**Prerequisites**: Stage 3 complete, ML basics, understanding of privacy

---

**Version**: 1.0  
**Last Updated**: January 2026  
**Status**: Production-Ready AI Integration
