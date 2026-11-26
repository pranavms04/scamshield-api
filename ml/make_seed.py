"""Writes ml/data/seed_messages.csv — a small hand-written starter dataset (label 1 = scam).
For a stronger model, append the public UCI SMS Spam Collection and Indian scam samples you collect."""
import csv
from pathlib import Path

SCAM = [
    "Dear customer your SBI account KYC has expired. Update immediately at http://bit.ly/sbi-kyc-upd or account will be blocked today",
    "Your HDFC netbanking will be suspended within 24 hours. Verify PAN card now: hdfc-verify.xyz/login",
    "Congratulations! You have won Rs 25,00,000 in KBC lottery. Call 9876543210 to claim your prize",
    "Earn Rs 5000 daily from home! Part time job, just like YouTube videos. WhatsApp 8123456789",
    "Your electricity connection will be disconnected tonight at 9.30pm due to unpaid bill. Call officer 7012345678 immediately",
    "You have received a cashback of Rs 2000. Enter your UPI PIN to receive the amount",
    "Instant loan approved Rs 50,000 with no documents. Download app now tinyurl.com/fastloan",
    "Your parcel is held at customs. Pay Rs 49 clearance fee at indiapost-track.top/pay",
    "FedEx: a package in your name contains illegal items. Mumbai police will call you. Press 1",
    "Income tax refund of Rs 15,490 approved. Submit bank details at it-refund.link to receive",
    "Dear user your Aadhaar is linked to money laundering case. CBI officer will contact you. Do not disconnect",
    "Invest Rs 10,000 and get Rs 50,000 in 7 days guaranteed. Join our crypto trading group now",
    "Your Paytm KYC is pending. Account will be blocked. Call customer care 9988776655 now",
    "Hello sir, I am from Amazon. You won iPhone 15 in lucky draw. Pay delivery charge Rs 199 to receive",
    "Work from home job: complete simple tasks and earn daily income Rs 3000. Registration fee Rs 500",
    "URGENT: your debit card is blocked. Share OTP received to unblock immediately",
    "Your SIM card will be deactivated in 2 hours. Complete e-KYC by calling 8899001122",
    "You are selected for Amazon part time job. Salary 30000 per month. Contact HR on WhatsApp",
    "Dear customer, Rs 9,999 debited from your account. If not you, click cutt.ly/stop-txn to cancel",
    "Get pre-approved personal loan at 0% interest. Limited offer, last chance today",
    "Your gas connection subsidy refund is pending. Update bank details at subsidy-refund.xyz",
    "Electricity board: bill not updated. Your power will be cut today. Contact 9123456780",
    "Send money to receive Rs 5000 reward. Scan QR and enter pin to claim cashback",
    "Your Netflix subscription has expired. Update payment at netflix-renew.top to avoid suspension",
    "Congratulations you have been selected for a Rs 1 crore lucky draw by RBI. Pay processing fee",
    "Telegram task job: rate hotels online and earn Rs 800 per task. Prepaid tasks pay double",
    "Your PAN card will be deactivated. Link now at pan-update.in/kyc within 24 hrs",
    "Hi mom my phone is broken this is my new number, please send Rs 20000 urgently to this UPI",
    "Customs department: gift parcel from UK requires Rs 35,000 duty payment immediately",
    "Your loan EMI is overdue. Pay now or your photos will be sent to your contacts",
]
LEGIT = [
    "Your OTP for login is 482913. Do not share it with anyone. -SBI",
    "Rs 450.00 debited from A/c XX1234 on 12-Nov via UPI to Swiggy. Avl bal Rs 12,340",
    "Hi, are we still meeting for lunch tomorrow at 1?",
    "Your Amazon order #402-1234567 has been shipped and will arrive by Thursday",
    "Reminder: your electricity bill of Rs 1,240 is due on 25 Nov. Pay via the KSEB app",
    "Your appointment with Dr. Menon is confirmed for Monday 10:30 AM",
    "Thanks for shopping at Lulu Mall. Your bill amount is Rs 2,380",
    "Can you send me the notes from today's class?",
    "Your Uber ride with Ravi is arriving in 3 minutes",
    "Happy birthday! Have a wonderful year ahead",
    "Your salary of Rs 42,000 has been credited to A/c XX5678",
    "Meeting moved to 4 PM, conference room B",
    "Your Jio recharge of Rs 299 is successful. Validity 28 days",
    "Flight 6E 532 from COK to BLR is on time. Gate 4",
    "Please review the pull request when you get time",
    "Your Zomato order is out for delivery",
    "Dad, I reached the hostel safely",
    "Your IRCTC ticket PNR 4512345678 is confirmed. Coach S4 Berth 32",
    "Library book due date is Friday. Renew online if needed",
    "Rs 1,000 received from Arun via UPI. Ref 334455667788",
    "The team outing is planned for Saturday. Please confirm attendance",
    "Your Flipkart refund of Rs 799 has been processed to the original payment method",
    "Interview scheduled with Infosys on 21 Nov at 10 AM. Join via the link in your email",
    "Your mutual fund SIP of Rs 2,000 was processed successfully",
    "Don't forget to bring the charger",
    "Your password was changed successfully. If this wasn't you, contact support from the official app",
    "Electricity bill paid successfully. Transaction ID KSEB2311",
    "Your gym membership renews next week",
    "Swiggy: rate your last order from Paragon",
    "Train is running 20 minutes late, will reach by 8",
]


def main() -> None:
    path = Path(__file__).parent / "data" / "seed_messages.csv"
    path.parent.mkdir(exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "label"])
        w.writerows([(t, 1) for t in SCAM] + [(t, 0) for t in LEGIT])
    print(f"wrote {len(SCAM) + len(LEGIT)} rows to {path}")


if __name__ == "__main__":
    main()
