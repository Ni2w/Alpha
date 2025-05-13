import logging
import requests
import json
import re
from bs4 import BeautifulSoup
from telegram import Update, Document
from telegram.ext import ApplicationBuilder, MessageHandler, CommandHandler, ContextTypes, filters

# --- CONFIG ---
BOT_TOKEN = "8153748905:AAGp03pGvNcuL7CAhcOV92jGv2c9opX-BVU"
logging.basicConfig(level=logging.INFO)

# --- STORAGE ---
user_data = {}

# --- HELPERS ---
def extract_stripe_info(html):
    soup = BeautifulSoup(html, "html.parser")
    pk = None
    stripe_type = None

    scripts = soup.find_all("script")
    for script in scripts:
        if script.string and 'pk_live_' in script.string:
            match = re.search(r'pk_live_[0-9a-zA-Z]+', script.string)
            if match:
                pk = match.group()

    if "setup_intents" in html:
        stripe_type = "setup_intent"
    elif "payment_methods" in html:
        stripe_type = "payment_method"
    elif "tokens" in html:
        stripe_type = "token"
    elif "sources" in html:
        stripe_type = "source"

    return pk, stripe_type

async def fetch_add_payment_page(url, session):
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html,application/xhtml+xml",
    }
    response = session.get(url, headers=headers)
    return response.text if response.ok else None

def create_payment_method(card):
    url = "https://api.stripe.com/v1/payment_methods"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "type": "card",
        "card[number]": card[0],
        "card[exp_month]": card[1],
        "card[exp_year]": card[2],
        "card[cvc]": card[3],
    }
    return requests.post(url, headers=headers, data=data)

def submit_to_stripe(card, stripe_type, pk):
    pm_res = create_payment_method(card)
    if pm_res.status_code != 200:
        return pm_res.text

    pm_id = pm_res.json().get("id")

    if stripe_type == "setup_intent":
        endpoint = "https://api.stripe.com/v1/setup_intents"
        data = {"payment_method": pm_id, "confirm": "true", "client_secret": f"{pk}_secret_123"}
    elif stripe_type == "payment_method":
        endpoint = "https://api.stripe.com/v1/payment_methods"
        data = {"payment_method": pm_id}
    elif stripe_type == "token":
        endpoint = "https://api.stripe.com/v1/tokens"
        data = {
            "card[number]": card[0],
            "card[exp_month]": card[1],
            "card[exp_year]": card[2],
            "card[cvc]": card[3],
        }
    elif stripe_type == "source":
        endpoint = "https://api.stripe.com/v1/sources"
        data = {
            "type": "card",
            "card[number]": card[0],
            "card[exp_month]": card[1],
            "card[exp_year]": card[2],
            "card[cvc]": card[3],
        }
    else:
        return json.dumps({"error": "Unsupported Stripe API type"})

    headers = {"Authorization": f"Bearer {pk}"}
    res = requests.post(endpoint, headers=headers, data=data)
    return res.text

def parse_card(combo):
    parts = combo.strip().split("|")
    return parts if len(parts) == 4 else None

# --- COMMANDS ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome to Stripe Blade.\nUse /addsitelogin to begin.")

async def addsitelogin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Send the full Add Payment Method URL of the site.")

async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    user_id = update.effective_user.id

    session = requests.Session()
    html = await context.application.run_in_thread(fetch_add_payment_page, url, session)
    if not html:
        await update.message.reply_text("Failed to load page.")
        return

    pk, api_type = extract_stripe_info(html)
    if not pk or not api_type:
        await update.message.reply_text("Failed to extract Stripe info.")
        return

    user_data[user_id] = {"url": url, "pk": pk, "api": api_type}
    await update.message.reply_text(f"Saved.\nDetected:\nPK: {pk}\nAPI: {api_type}")

async def chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_data:
        await update.message.reply_text("Use /addsitelogin first.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /chk cc|mm|yy|cvv")
        return

    combo = context.args[0]
    card = parse_card(combo)
    if not card:
        await update.message.reply_text("Invalid format.")
        return

    info = user_data[user_id]
    res = await context.application.run_in_thread(submit_to_stripe, card, info["api"], info["pk"])
    await update.message.reply_text(f"`{res}`", parse_mode="Markdown")

async def handle_txt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if doc.mime_type != "text/plain":
        await update.message.reply_text("Upload a .txt file only.")
        return

    user_id = update.effective_user.id
    if user_id not in user_data:
        await update.message.reply_text("Use /addsitelogin first.")
        return

    file = await doc.get_file()
    content = await file.download_as_bytearray()
    lines = content.decode().splitlines()

    info = user_data[user_id]
    for line in lines:
        card = parse_card(line)
        if card:
            res = await context.application.run_in_thread(submit_to_stripe, card, info["api"], info["pk"])
            await update.message.reply_text(f"`{res}`", parse_mode="Markdown")

# --- MAIN ---
app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("addsitelogin", addsitelogin))
app.add_handler(CommandHandler("chk", chk))
app.add_handler(MessageHandler(filters.TEXT & filters.Regex(r"^https?://"), handle_url))
app.add_handler(MessageHandler(filters.Document.MimeType("text/plain"), handle_txt))

app.run_polling()
