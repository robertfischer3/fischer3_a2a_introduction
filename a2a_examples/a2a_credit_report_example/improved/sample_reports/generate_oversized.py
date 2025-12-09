#!/usr/bin/env python3
"""
Generate an oversized credit report for testing DoS vulnerabilities.
Creates a 10MB+ JSON file with many duplicate accounts.
"""
import json

def generate_oversized_report():
    """Generate a report with thousands of accounts to exceed size limits"""
    
    report = {
        "report_id": "CR-2025-HUGE",
        "report_date": "2025-01-15T10:30:00Z",
        "bureau": "Oversized Data Bureau",
        "subject": {
            "ssn": "999-99-9999",
            "name": "Test Subject DoS Attack",
            "dob": "1990-01-01",
            "address": "1234 Memory Exhaustion Lane, DoS City, ST 99999",
            "phone": "555-999-9999",
            "email": "huge@example.com"
        },
        "credit_score": {
            "score": 700,
            "model": "FICO 8",
            "date": "2025-01-15",
            "factors": ["Too many accounts to track properly"]
        },
        "accounts": [],
        "inquiries": [],
        "public_records": [],
        "collections": [],
        "summary": {}
    }
    
    # Generate 50,000 fake accounts to make file huge
    print("Generating 50,000 accounts...")
    for i in range(50000):
        account = {
            "account_id": f"ACCT-{i:06d}",
            "creditor": f"Creditor {i} with a very long name to increase size",
            "type": "credit_card",
            "status": "open",
            "opened": "2020-01-01",
            "balance": i * 100,
            "credit_limit": i * 1000,
            "payment_status": "current",
            "payment_history": f"Payment history for account {i} " * 10,
            "notes": f"Additional notes to increase file size " * 20
        }
        report["accounts"].append(account)
        
        # Add inquiry for every 10th account
        if i % 10 == 0:
            inquiry = {
                "date": "2025-12-01",
                "creditor": f"Creditor {i}",
                "type": "hard",
                "purpose": f"Application number {i}"
            }
            report["inquiries"].append(inquiry)
    
    report["summary"] = {
        "total_accounts": len(report["accounts"]),
        "total_inquiries": len(report["inquiries"])
    }
    
    # Write to file
    output_file = "oversized_report.json"
    print(f"Writing to {output_file}...")
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    
    # Check file size
    import os
    size_mb = os.path.getsize(output_file) / (1024 * 1024)
    print(f"✅ Generated file size: {size_mb:.2f} MB")
    print(f"   This will cause memory exhaustion in vulnerable implementations!")

if __name__ == "__main__":
    generate_oversized_report()
