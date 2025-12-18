from email_checks import analyse_email


def print_report(result: dict) -> None:
    print("\n" + "=" * 50)
    print("OSINT EMAIL RISK REPORT")
    print("=" * 50)

    print(f"\nEmail Checked: {result.get('input_email')}")
    print(f"Syntax Valid: {result.get('is_syntax_valid')}")
    print(f"Domain: {result.get('domain')}")
    print(f"Domain Resolves DNS: {result.get('domain_resolves_dns')}")

    risk_level = result.get("risk_level")
    risk_score = result.get("risk_score")

    print("\n--- VERDICT ---")
    if risk_level == "HIGH":
        print(f"⚠️  SCAM LIKELY (HIGH RISK – {risk_score}/100)")
    elif risk_level == "MEDIUM":
        print(f"⚠️  USE CAUTION (MEDIUM RISK – {risk_score}/100)")
    else:
        print(f"✅  LOW RISK ({risk_score}/100)")

    print("\n--- RISK REASONS ---")
    for reason in result.get("risk_reasons", []):
        print(f"• {reason}")

    print("\n--- NOTES ---")
    print(result.get("notes"))

    print("\nThis assessment is heuristic and should be used alongside")
    print("email content, headers, and user context.")
    print("=" * 50 + "\n")


def main() -> None:
    print("OSINT Email Verification Tool (V3)")
    print("-" * 40)

    email = input("Enter an email address: ").strip()
    result = analyse_email(email)
    print_report(result)


if __name__ == "__main__":
    main()
