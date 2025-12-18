from email_checks import analyse_email


def main() -> None:
    print("OSINT Email Verification Tool (V1)")
    print("-" * 36)

    email = input("Enter an email address: ").strip()
    result = analyse_email(email)

    print("\nResult")
    print("-" * 36)
    for k, v in result.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
