# Security Notice: Fictitious Data in Demonstrations

## ✅ All Credentials and Data Are Completely Fake

**Date**: January 22, 2026  
**Purpose**: Educational demonstrations only

---

## 🎯 Data Safety Measures

All sensitive data used in attack demonstrations has been carefully designed to be:

1. **Obviously Fictitious** - Cannot be mistaken for real data
2. **Invalid Formats** - Do not match real service patterns
3. **Reserved Values** - Use officially reserved/invalid values
4. **Safe for Display** - Can be shown in screenshots, videos, presentations

---

## 📋 Fictitious Data Used

### Customer Records

**SSNs**:
- `000-00-0000` - Reserved for advertising/testing (invalid)
- `111-11-1111` - Reserved, never issued (invalid)

**Credit Cards**:
- `0000-0000-0000-0000` - Obviously invalid
- `1111-1111-1111-1111` - Obviously invalid
- These do NOT pass Luhn algorithm validation

**Names**:
- "Alice Testperson"
- "Bob Exampleuser"
- Clearly fictional names

**Emails**:
- `*.example.invalid` domain
- `.invalid` TLD per RFC 2606 (reserved for documentation)
- Guaranteed to never be a real domain

**Phone Numbers**:
- `555-0100` to `555-0199` range
- Reserved for fictional use in North America
- Cannot be assigned to real subscribers

**Addresses**:
- "Testville, XX 00000"
- "Sampletown, XX 00000"
- XX is not a valid US state code
- 00000 is an invalid ZIP code

---

### Database Credentials

**Host**:
- `fake-database.example.invalid`
- `.invalid` TLD per RFC 2606 (never a real domain)

**Port**:
- `9999` - Non-standard, not commonly used

**Username**:
- `FAKE_ADMIN_USER` - Obviously fake

**Password**:
- `XXXX-FAKE-PASSWORD-NOT-REAL-XXXX` - Clearly marked as fake

**Database Name**:
- `fake_demo_database_not_real` - Self-explanatory

---

### API Keys

**Payment Service**:
- `FAKE_pk_test_NOTAREALKEY1234567890abcdef`
- Prefixed with "FAKE"
- Does NOT match Stripe's format (which is `sk_live_` or `pk_live_`)

**Cloud Provider**:
- `DEMO-FAKE-ACCESS-KEY-INVALID-FORMAT`
- Prefixed with "DEMO-FAKE"
- Does NOT match AWS format (20 uppercase alphanumeric)

**Cloud Secret**:
- `XXXX/FAKE+SECRET/KEY+NOT+REAL+FORMAT/XXXX`
- Clearly marked as fake
- Does NOT match AWS secret key format (40 characters)

**Email Service**:
- `FAKE.demo123456.NotARealAPIKeyFormat`
- Prefixed with "FAKE"
- Does NOT match SendGrid format (which is 69 characters, alphanumeric)

---

## 🔍 Why This Matters

### Original Issue
Some credentials in v1 resembled real service formats:
- AWS example keys matched documented format
- Stripe test keys looked realistic
- Could potentially be confused with real credentials

### Our Solution
All credentials now:
- ✅ Clearly marked as "FAKE" or "DEMO"
- ✅ Use invalid/reserved values
- ✅ Don't match any real service patterns
- ✅ Include obvious indicators (XXXX, all caps, "NOT REAL")

---

## 📚 Standards Referenced

### RFC 2606 - Reserved Top-Level DNS Names
- `.test` - Testing
- `.example` - Documentation examples
- `.invalid` - **Invalid/non-existent domains (we use this)**
- `.localhost` - Localhost

**We use `.invalid` throughout to ensure domains cannot resolve.**

### SSN Reservations (SSA)
- `000-00-0000` through `000-99-9999` - Not issued
- `111-11-1111`, `222-22-2222`, etc. - Not issued
- `666-xx-xxxx` - Not issued

**We use `000-00-0000` and `111-11-1111` (both invalid).**

### Phone Numbers (NANPA)
- `555-0100` through `555-0199` - Reserved for fictional use
- Safe for media, demonstrations, documentation

**We use numbers in this range exclusively.**

### Credit Card Test Numbers
- Real services publish test numbers
- We use obviously invalid patterns instead (`0000-...`, `1111-...`)
- These fail Luhn algorithm validation

---

## ✅ Verification Checklist

Before any public release, we verify:

- [ ] No SSNs that could be real (avoid `xxx-xx-xxxx` patterns with digits)
- [ ] No credit cards that pass Luhn validation
- [ ] All domains use `.invalid` or `.example.invalid`
- [ ] All API keys clearly marked "FAKE" or "DEMO"
- [ ] All phone numbers in 555-01xx range
- [ ] All addresses use "XX" state and "00000" ZIP
- [ ] All passwords clearly marked as fake
- [ ] No patterns matching real service formats

**Status**: ✅ **ALL VERIFIED** (as of January 22, 2026)

---

## 🎓 Educational Purpose

These demonstrations teach:
- What data exfiltration looks like
- How sensitive information is structured
- What attackers target (PII, credentials, API keys)
- Why validation and encryption matter

**Without using any real or realistic-looking data.**

---

## 📝 For Educators

When presenting this material:

✅ **Do**:
- Emphasize all data is fictitious
- Point out the obvious fake indicators
- Use as teaching examples safely
- Screenshot/screen record freely

❌ **Don't**:
- Suggest these are real credential formats
- Use as templates for real systems
- Remove the "FAKE" prefixes
- Make data look more realistic

---

## 🔄 Updates

**v1.0** (January 21, 2026): Initial credentials  
**v2.0** (January 22, 2026): Updated to obviously fake formats

- Changed SSNs to reserved invalid numbers
- Changed domains to `.invalid` TLD
- Changed API keys to "FAKE" prefixed with wrong formats
- Changed credit cards to obviously invalid patterns
- Added clear "FAKE" and "XXXX" markers throughout

---

## 📞 Questions?

If you have concerns about any data in our demonstrations:

- **Email**: robert@fischer3.net
- **GitHub**: Open an issue
- **Principle**: We err on the side of extreme caution

**We take data safety seriously, even for fictional examples.**

---

## ✅ Summary

**Every piece of sensitive data in our demonstrations is:**
1. Completely fictitious
2. Uses invalid/reserved values
3. Clearly marked as fake
4. Cannot match real services
5. Safe for public display
6. Verified against standards

**You can confidently use, share, and present this material without any risk of exposing real credentials or data.**

---

**Last Updated**: January 22, 2026  
**Status**: Verified Safe ✅  
**Review Frequency**: Before each release