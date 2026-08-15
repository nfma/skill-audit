# Heuristic Compliance Review

**Generated:** 2026-03-23
**Framework:** Vietnam AI Law 2026, EU AI Act, GDPR

---

## Executive Summary

| Skill | Vietnam indicators | EU AI Act indicators | GDPR indicators | Review priority |
|-------|---------------|-----------|------|--------------|
| skill-audit | ✅ No gaps flagged | ✅ No gaps flagged | ✅ No gaps flagged | Low |
| security-review | ⚠️ Review indicators | ✅ No gaps flagged | ⚠️ Review indicators | Medium |
| tdd-workflow | ✅ No gaps flagged | ✅ No gaps flagged | ✅ No gaps flagged | Low |
| writing-skills | ❌ Missing indicators | ❌ Missing indicators | ❌ Missing indicators | High |

This example shows documentation heuristics only. It does not establish legal compliance or non-compliance.

---

## Detailed Findings

### skill-audit ✅

**Vietnam AI Law 2026:**
- ✅ VN-AI-001: No data localization issues detected
- ✅ VN-AI-002: No user data collection without consent
- ✅ VN-AI-003: AI disclosure present in outputs
- ✅ VN-AI-004: No high-risk decision-making
- ✅ VN-AI-005: Data minimization practices observed
- ✅ VN-AI-006: Explanations provided for outputs
- ✅ VN-AI-007: No discriminatory patterns detected

**EU AI Act:**
- ✅ EU-AI-001: Risk assessment documented
- ✅ EU-AI-002: Data governance practices in place
- ✅ EU-AI-003: Technical documentation maintained
- ✅ EU-AI-004: Record keeping adequate
- ✅ EU-AI-005: Transparency requirements met

**GDPR:**
- ✅ GDPR-001: Lawful basis identified (legitimate interest)
- ✅ GDPR-002: Data subject rights supported
- ✅ GDPR-003: Privacy by design implemented
- ✅ GDPR-004: No high-risk processing
- ✅ GDPR-005: No breach notification needed
- ✅ GDPR-006: No international transfers

---

### security-review ⚠️

**Vietnam AI Law 2026:**
- ✅ VN-AI-001: No data localization issues
- ⚠️ VN-AI-002: Review user consent mechanism in examples/
- ✅ VN-AI-003: AI disclosure present

**EU AI Act:**
- ✅ EU-AI-001 through EU-AI-005: No documentation gaps flagged

**GDPR:**
- ⚠️ GDPR-001: Document lawful basis for processing
- ⚠️ GDPR-003: Review privacy by design in examples/

**Recommendations:**
1. Add explicit consent prompts in example code
2. Document GDPR lawful basis in README
3. Review example files for PII in test data

---

### tdd-workflow ✅

**All frameworks:** No documentation gaps flagged

No heuristic documentation gaps detected. The example indicates:
- Minimal data collection
- No user data processing
- No external API calls with user data

---

### writing-skills ❌

**Vietnam AI Law 2026:**

| ID | Requirement | Status | Finding |
|----|-------------|--------|---------|
| VN-AI-001 | Data Localization | ❌ | Skill sends user code to external LLM without data localization |
| VN-AI-002 | User Consent | ❌ | No consent mechanism before processing user code |
| VN-AI-003 | Transparency | ⚠️ | Partial - AI disclosure not always present |
| VN-AI-004 | Human Oversight | ❌ | No human oversight for code generation |
| VN-AI-005 | Data Minimization | ❌ | Collects full user codebase for processing |
| VN-AI-006 | Right to Explanation | ⚠️ | Limited explanation provided |
| VN-AI-007 | Bias Prevention | ⚠️ | No bias testing documented |

**EU AI Act:**

| ID | Requirement | Status | Finding |
|----|-------------|--------|---------|
| EU-AI-001 | Risk Assessment | ❌ | No documented risk assessment |
| EU-AI-002 | Data Governance | ❌ | User code stored externally |
| EU-AI-003 | Technical Documentation | ⚠️ | Incomplete documentation |
| EU-AI-004 | Record Keeping | ❌ | No logs of processing activities |
| EU-AI-005 | Transparency | ⚠️ | AI nature not always disclosed |

**GDPR:**

| ID | Requirement | Status | Finding |
|----|-------------|--------|---------|
| GDPR-001 | Lawful Basis | ❌ | No documented lawful basis |
| GDPR-002 | Data Subject Rights | ❌ | No mechanism for rights requests |
| GDPR-003 | Privacy by Design | ❌ | Not implemented |
| GDPR-004 | DPIA | ❌ | Not conducted |
| GDPR-005 | Breach Notification | ❌ | No procedures in place |
| GDPR-006 | International Transfers | ❌ | Transfers to US without safeguards |

**High-priority documentation gaps:**
1. User code is described as being sent to external LLM services
2. No consent mechanism is documented before processing
3. No data-subject-rights mechanism is documented
4. Safeguards for international transfers are not documented

---

## Remediation Priority

### High Priority (writing-skills)

1. **Data Localization**: Implement option to process locally or in Vietnam
2. **Consent**: Add consent prompt before processing user code
3. **Transparency**: Ensure AI disclosure in all outputs
4. **Lawful Basis**: Document processing basis (likely consent or contract)
5. **Data Subject Rights**: Implement access, deletion, portability

### Medium Priority (security-review)

1. **Consent**: Add consent mechanism in examples
2. **Privacy by Design**: Document in README

### Low Priority (tdd-workflow, skill-audit)

No action required.

---

## References

- [Vietnam Government legal database - Law No. 134/2025/QH15](https://vanban.chinhphu.vn/?docid=216334&orggroupid=1&pageid=27160)
- [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)
- [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
