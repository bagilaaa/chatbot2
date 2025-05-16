import asyncio
import subprocess
import requests
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, filters, MessageHandler
import openai
import traceback
import uuid
import os

# OpenAI API key
openai.api_key = "#api"

# It stores last analysis
last_analysis = {}

# Admin user ID (replace with your real Telegram ID)
ADMIN_USER_ID = #adminid

# Suspicious keywords and domain restrictions
SUSPICIOUS_KEYWORDS = [ "gov", "gov.kz", "egov", "egov.kz", "elicense", "adilet", "bank", "kaspi", "halyk", "fortebank", "jysan", "centercredit", "sber", "homecredit", "eubank",
    "qiwi", "webmoney", "paypal", "stripe", "visa", "mastercard", "login", "auth", "idp", "cabinet", "lk", "passport", "iin", "salyk", "kgd", "kzportal", "admin", "adminpanel", "api.php"]
WHITELISTED_DOMAINS = ["localhost", "127.0.0.1", "example.com"]
BLOCKED_USERS = set()

# Asynchronous /start command
async def start(update, context):
    menu_text = (
        "*Hello! I am a bot for web penetration testing.*\n"
        "Here's what I can do:\n"
        "1. */chat* - Ask me any penetration testing questions!\n"
        "2. */code* - Send me your code for vulnerability analysis.\n"
        "3. */pentest* - Run penetration testing tools.\n\n"
        "*Enter a command to get started!*"
    )
    await update.message.reply_text(menu_text, parse_mode='Markdown')

async def pentest_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    menu_text = (
        "*Pentesting Tools Menu:*\n"
        "1. */sqlmap <URL>* - Detect SQL injection flaws.\n"
        "2. */fetch <URL>* - Extract links to analyze site structure.\n"
        "3. */subdomains <URL>* - Search for subdomains.\n"
        "4. */ssrf <URL>* - Check for SSRF flaws.\n"
        "5. */nikto <URL>* - Scan for common web vulnerabilities.\n"
        "6. */nuclei <URL>* - Scan with vulnerability templates.\n"
        "7. */waf <URL>* - Detect Web Application Firewall protection.\n"
        "8. */analyze* - Receive the analysis based on the pentest results.\n"
    )
    await update.message.reply_text(menu_text, parse_mode='Markdown')

# Asynchronous /chat command
async def chat(update, context):
    user_input = update.message.text.strip()

    try:
        # Send user input for a response
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",  # Use a suitable GPT model
            messages=[{"role": "system", "content": "You are an expert in web application security and penetration testing. Answer the following user questions."},
                      {"role": "user", "content": user_input}]
        )

        # Get response from GPT
        gpt_reply = response['choices'][0]['message']['content']

        # Send a simplified response
        await update.message.reply_text(gpt_reply, parse_mode='Markdown')

    except Exception as e:
        error_message = traceback.format_exc()
        print(f"Error: {error_message}")
        await update.message.reply_text("An error occurred while processing your request. Please try again later.")

# Asynchronous /code command
async def code(update, context):
    user_input = update.message.text.strip()

    if user_input == "/code":
        # Ask to send code
        await update.message.reply_text("*Please send me the code you'd like to analyze for vulnerabilities.*")
        return

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",  # Use a suitable GPT model
            messages=[{"role": "system", "content": "You are an expert in web application security. Please analyze the code and identify any vulnerabilities. Provide only the name and a brief definition of the vulnerability."},
                      {"role": "user", "content": user_input}]
        )

        gpt_reply = response['choices'][0]['message']['content']

        # Save analysis for report
        last_analysis['code_analysis'] = gpt_reply

        analysis_message = (
            "*Vulnerability Summary:*\n"
            f"{gpt_reply}\n\n"
            "*For a detailed report, use the /report command.*"
        )

        await update.message.reply_text(analysis_message, parse_mode='Markdown')

    except Exception as e:
        error_message = traceback.format_exc()
        print(f"Error: {error_message}")
        await update.message.reply_text("An error occurred while processing your request. Please try again later.")

# /report command
async def report(update, context):
    try:
        if 'code_analysis' in last_analysis:
            analysis = last_analysis['code_analysis']

            # Generate a report
            report_text = "*Vulnerability Report:*\n\n"

            # Include a brief summary of the vulnerabilities identified
            report_text += f"*Vulnerabilities Identified:*\n{analysis[:1500]}\n\n"

            # Protection methods and suggested tools
            prompt = f"Based on the following vulnerability analysis: {analysis[:1500]}, suggest protection methods and tools for fixing these vulnerabilities."
            response = openai.ChatCompletion.create(
                model="gpt-4o-mini",
                messages=[{"role": "system", "content": "You are an expert in web application security."},
                          {"role": "user", "content": prompt}]
            )
            recommendations = response['choices'][0]['message']['content']

            # Generated recommendations
            report_text += "*Protection Methods and Tools:*"
            report_text += "\n" + recommendations

            # If the message exceeds Telegram's character limit
            if len(report_text) > 4096:
                # If too large, split it into multiple messages
                part1 = report_text[:2000]
                part2 = report_text[2000:]
                await update.message.reply_text(part1, parse_mode='Markdown')
                await update.message.reply_text(part2, parse_mode='Markdown')
            else:
                await update.message.reply_text(report_text, parse_mode='Markdown')
        else:
            await update.message.reply_text("No code analysis has been performed yet. Please run the /code command first.", parse_mode='Markdown')
    except Exception as e:
        error_message = traceback.format_exc()
        print(f"Error while generating the report: {error_message}")
        await update.message.reply_text("An error occurred while generating the report. Please try again later.")


# PENTEST MENU

# Function to detect suspicious URLs
def is_suspicious_url(url):
    url_lower = url.lower()
    if not any(allowed in url_lower for allowed in WHITELISTED_DOMAINS):
        if any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS):
            return True
    return False

# Admin-only block command
def is_admin(user_id):
    return user_id == ADMIN_USER_ID

async def block_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.message.from_user.id):
        await update.message.reply_text("⛔ You are not authorized to use this command.")
        return

    if not context.args:
        await update.message.reply_text("Usage: /block <user_id>")
        return

    try:
        user_id = int(context.args[0])
        BLOCKED_USERS.add(user_id)
        await update.message.reply_text(f"✅ User {user_id} has been blocked.")
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID.")

async def nikto_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    if user_id in BLOCKED_USERS:
        await update.message.reply_text("⛔ You are blocked from using this bot.")
        return

    url = ' '.join(context.args)
    if not url:
        await update.message.reply_text("Please provide a URL to scan with Nikto. Example: /nikto https://example.com")
        return

    if is_suspicious_url(url):
        user = update.message.from_user
        log_entry = (
            f"⚠️ Suspicious activity detected!\n"
            f"User: {user.id}\nUsername: @{user.username}\nName: {user.first_name} {user.last_name}\n"
            f"Command: /nikto\nURL: {url}\n"
        )
        await context.bot.send_message(chat_id=ADMIN_USER_ID, text=log_entry)
        with open("suspicious_users.log", "a") as log:
            log.write(log_entry + "\n")
        await update.message.reply_text("🚫 You are not allowed to scan this domain.")
        return

    try:
        await update.message.reply_text(f"🔍 Starting Nikto scan for {url}...")

        command = ["nikto", "-h", url]
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        full_output = []
        while True:
            output = await process.stdout.readline()
            if output:
                full_output.append(output.decode().strip())
            else:
                break

        # Add stderr if present
        stderr = await process.stderr.read()
        if stderr:
            full_output.append("\nErrors:\n" + stderr.decode().strip())

        return_code = await process.wait()
        if return_code != 0:
            full_output.append(f"\nNikto exited with code {return_code}.")

        # Save result to a unique file
        filename = f"nikto_output_{user_id}_{uuid.uuid4().hex}.txt"
        with open(filename, "w") as file:
            file.write("\n".join(full_output))

        # Send file as document
        with open(filename, "rb") as file:
            await update.message.reply_document(document=file, caption="Nikto Scan Results")

        await update.message.reply_text("✅ Nikto scan completed. To start a new scan, send /nikto <URL>.")

        # Clean up
        os.remove(filename)

    except Exception as e:
        await update.message.reply_text(f"❌ An error occurred: {e}")

# Function for scanning with SQLMap

async def sqlmap_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    if user_id in BLOCKED_USERS:
        await update.message.reply_text("⛔ You are blocked from using this bot.")
        return

    url = ' '.join(context.args)
    if not url:
        await update.message.reply_text("Please provide a URL to scan with SQLMap. Example: /sqlmap https://example.com")
        return

    if is_suspicious_url(url):
        user = update.message.from_user
        log_entry = (
            f"⚠️ Suspicious activity detected!\n"
            f"User: {user.id}\nUsername: @{user.username}\nName: {user.first_name} {user.last_name}\n"
            f"Command: /sqlmap\nURL: {url}\n"
        )
        await context.bot.send_message(chat_id=ADMIN_USER_ID, text=log_entry)
        with open("suspicious_users.log", "a") as log:
            log.write(log_entry + "\n")
        await update.message.reply_text("🚫 You are not allowed to scan this domain.")
        return

    try:
        await update.message.reply_text(f"Starting SQLMap scan for {url}...")

        command = ["sqlmap", "-u", url, "--batch"]
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        full_output = []
        while True:
            output = await process.stdout.readline()
            if output:
                output_text = output.decode().strip()
                if output_text:
                    full_output.append(output_text)
            else:
                break

        # Уникальное имя файла
        filename = f"sqlmap_output_{user_id}_{uuid.uuid4().hex}.txt"
        with open(filename, "w") as file:
            file.write("\n".join(full_output))

        with open(filename, "rb") as file:
            await update.message.reply_document(document=file, caption="SQLMap Scan Results")

        stderr = await process.stderr.read()
        if stderr:
            stderr_text = stderr.decode().strip()
            if stderr_text:
                await update.message.reply_text(f"Error: {stderr_text}")

        return_code = await process.wait()
        if return_code != 0:
            await update.message.reply_text(f"SQLMap exited with code {return_code}.")

        await update.message.reply_text("Scan completed. To start a new scan, send /sqlmap <URL>.")

        # Удаляем файл после отправки
        os.remove(filename)

    except Exception as e:
        await update.message.reply_text(f"An error occurred: {e}")

# Function for extracting all links from a web page
async def fetchpage(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    if user_id in BLOCKED_USERS:
        await update.message.reply_text("⛔ You are blocked from using this bot.")
        return

    url = ' '.join(context.args)
    if not url:
        await update.message.reply_text("Please provide a URL to extract links from. Example: /fetchpage https://example.com")
        return

    if is_suspicious_url(url):
        user = update.message.from_user
        log_entry = (
            f"⚠️ Suspicious activity detected!\n"
            f"User: {user.id}\nUsername: @{user.username}\nName: {user.first_name} {user.last_name}\n"
            f"Command: /fetchpage\nURL: {url}\n"
        )
        await context.bot.send_message(chat_id=ADMIN_USER_ID, text=log_entry)
        with open("suspicious_users.log", "a") as log:
            log.write(log_entry + "\n")
        await update.message.reply_text("🚫 You are not allowed to scan this domain.")
        return

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        links = soup.find_all('a', href=True)
        if links:
            links_list = "\n".join([link['href'] for link in links])
            await update.message.reply_text(f"Found links on the page:\n{links_list}")
        else:
            await update.message.reply_text("No links found on the page.")
    except requests.exceptions.RequestException as e:
        await update.message.reply_text(f"An error occurred while fetching the page: {e}")

async def subdomain_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    if user_id in BLOCKED_USERS:
        await update.message.reply_text("⛔ You are blocked from using this bot.")
        return

    if not context.args:
        await update.message.reply_text("⚠ Specify the domain to search for subdomains. Example: /subdomains example.com")
        return

    domain = context.args[0]
    if is_suspicious_url(domain):
        user = update.message.from_user
        log_entry = (
            f"⚠️ Suspicious activity detected!\n"
            f"User: {user.id}\nUsername: @{user.username}\nName: {user.first_name} {user.last_name}\n"
            f"Command: /subdomains\nDomain: {domain}\n"
        )
        await context.bot.send_message(chat_id=ADMIN_USER_ID, text=log_entry)
        with open("suspicious_users.log", "a") as log:
            log.write(log_entry + "\n")
        await update.message.reply_text("🚫 You are not allowed to scan this domain.")
        return

    await update.message.reply_text(f"🔍 Launching a subdomain search for {domain}...")

    try:
        process = subprocess.Popen(["subfinder", "-d", domain, "-silent"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=180)

        if stdout:
            subdomains = stdout.strip().split("\n")
            message = "✅ Found subdomains::\n" + "\n".join(subdomains)

            max_length = 4096
            for i in range(0, len(message), max_length):
                await update.message.reply_text(message[i:i + max_length])

        elif stderr:
            await update.message.reply_text(f"❌ Error subfinder: {stderr}")
        else:
            await update.message.reply_text("❌ No subdomains were found.")

    except subprocess.TimeoutExpired:
        await update.message.reply_text("❌ Error: The subfinder has been running for too long. Try again later.")

# SSRF check
async def ssrf_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    if user_id in BLOCKED_USERS:
        await update.message.reply_text("⛔ You are blocked from using this bot.")
        return

    if not context.args:
        await update.message.reply_text(
            "⚠ Specify the URL with the parameter that can be tested. Example: /ssrf https://example.com/api?url=")
        return

    base_url = context.args[0]
    if is_suspicious_url(base_url):
        user = update.message.from_user
        log_entry = (
            f"⚠️ Suspicious activity detected!\n"
            f"User: {user.id}\nUsername: @{user.username}\nName: {user.first_name} {user.last_name}\n"
            f"Command: /ssrf\nURL: {base_url}\n"
        )
        await context.bot.send_message(chat_id=ADMIN_USER_ID, text=log_entry)
        with open("suspicious_users.log", "a") as log:
            log.write(log_entry + "\n")
        await update.message.reply_text("🚫 You are not allowed to scan this domain.")
        return

    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",  # AWS Instance Metadata Service
        "http://127.0.0.1:80",
        "http://localhost:8080",
        "http://internal.example.com",
    ]

    results = []
    await update.message.reply_text(f"🔍 Running an SSRF scan for {base_url}...")

    for payload in ssrf_payloads:
        test_url = base_url + payload
        try:
            response = requests.get(test_url, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                results.append(f"⚠️ Possible SSRF vulnerability! The server responded to {test_url}")
        except requests.exceptions.RequestException as e:
            results.append(f"ℹ️ Couldn't verify {test_url}: {e}")

    if results:
        await update.message.reply_text("\n".join(results), parse_mode='Markdown')
    else:
        await update.message.reply_text("✅ No SSRF vulnerabilities were found.")

async def nuclei_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = ' '.join(context.args).strip()
    if not url:
        await update.message.reply_text("⚠ Укажите URL. Пример: /nuclei https://example.com")
        return

    if is_suspicious_url(url):
        user = update.message.from_user
        log_entry = (
            f"⚠️ Suspicious activity detected!\n"
            f"User: {user.id}\nUsername: @{user.username}\nName: {user.first_name} {user.last_name}\n"
            f"Command: /nuclei\nURL: {url}\n"
        )
        await context.bot.send_message(chat_id=ADMIN_USER_ID, text=log_entry)
        with open("suspicious_users.log", "a") as log:
            log.write(log_entry + "\n")
        await update.message.reply_text("🚫 You are not allowed to scan this domain.")
        return

    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'

    status_msg = await update.message.reply_text(f"🚀 Начинаю сканирование {url}... Это может занять несколько минут")

    # Отправляем сообщение о начале сканирования
    status_msg = await update.message.reply_text(f"🚀 Начинаю сканирование {url}... Это может занять несколько минут")

    try:
        # Упрощённая команда для теста (без severity фильтра)
        command = [
            "/Users/bagilazhusupova/go/bin/nuclei",
            "-u", url,
            "-silent",
            "-timeout", "300",  # Таймаут Nuclei (5 мин)
            "-rate-limit", "50",  # Ограничение запросов/сек
            "-templates", "misconfiguration,security-misconfig",  # Только конфигурации
            "-severity", "medium,high,critical"  # Пропустить info
        ]

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Увеличиваем общий таймаут до 7 минут
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=420)
        except asyncio.TimeoutError:
            process.kill()
            await status_msg.edit_text("🕒 Сканирование прервано: превышено максимальное время (7 минут)")
            return

        result = stdout.decode().strip()
        error = stderr.decode().strip()

        # Удаляем статусное сообщение
        await status_msg.delete()

        if result:
            # Отправляем файл если результат большой
            if len(result) > 2000:
                with open("nuclei_result.txt", "w") as f:
                    f.write(result)
                await update.message.reply_document(
                    document=open("nuclei_result.txt", "rb"),
                    caption=f"Результаты сканирования {url}"
                )
            else:
                await update.message.reply_text(f"🛡️ Результаты:\n{result}")
        else:
            await update.message.reply_text("✅ Nuclei не обнаружил уязвимостей.")

        if error:
            await update.message.reply_text(f"⚠️ Логи:\n{error[:1000]}")

    except Exception as e:
        await status_msg.edit_text(f"❌ Ошибка: {str(e)[:500]}")

async def waf_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = ' '.join(context.args)
    if not url:
        await update.message.reply_text("⚠ Укажите URL. Пример: /waf https://example.com")
        return

    if is_suspicious_url(url):
        user = update.message.from_user
        log_entry = (
            f"⚠️ Suspicious activity detected!\n"
            f"User: {user.id}\nUsername: @{user.username}\nName: {user.first_name} {user.last_name}\n"
            f"Command: /waf\nURL: {url}\n"
        )
        await context.bot.send_message(chat_id=ADMIN_USER_ID, text=log_entry)
        with open("suspicious_users.log", "a") as log:
            log.write(log_entry + "\n")
        await update.message.reply_text("🚫 You are not allowed to scan this domain.")
        return

    try:
        await update.message.reply_text(f"🛡 Проверяю наличие WAF на {url}...")

        process = await asyncio.create_subprocess_exec(
            "wafw00f", url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        result = stdout.decode().strip()
        error = stderr.decode().strip()

        if result:
            await update.message.reply_text(f"🔍 Результат:\n{result}")
        else:
            await update.message.reply_text("✅ WAF не обнаружен или сайт не отвечает.")

        if error:
            await update.message.reply_text(f"⚠️ Ошибка:\n{error}")

    except Exception as e:
        await update.message.reply_text(f"❌ Ошибка при запуске wafw00f: {e}")


async def analyze(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Send me a txt file with the report for analysis.")

# Функция для обработки команды /result
async def result(update: Update, context: ContextTypes.DEFAULT_TYPE):
    file_path = f"report_{update.message.from_user.id}.txt"
    try:
        with open(file_path, "r") as file:
            report_content = file.read()

        # Отправляем содержимое файла в OpenAI для анализа
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "You are an expert in web application security. Analyze the following pentesting report and suggest improvements."},
                      {"role": "user", "content": report_content}]
        )

        gpt_reply = response['choices'][0]['message']['content']

        max_length = 4096
        chunks = [gpt_reply[i:i + max_length] for i in range(0, len(gpt_reply), max_length)]

        for chunk in chunks:
            await update.message.reply_text(f"{chunk}", parse_mode='Markdown')

    except FileNotFoundError:
        await update.message.reply_text("The report file was not found. Please send the report file.")
    except Exception as e:
        await update.message.reply_text(f"An error occurred while analyzing the file: {e}")

# Функция для обработки загруженного файла
async def handle_report_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.document:
        file = await update.message.document.get_file()
        file_path = f"report_{update.message.from_user.id}.txt"
        await file.download_to_drive(file_path)
        await update.message.reply_text("The report file has been uploaded successfully. Use the /result command for analysis.")
    else:
        await update.message.reply_text("Please send a text file with the reports.")

# Основная функция для запуска бота
def main():
    telegram_token = "#token"
    application = Application.builder().token(telegram_token).build()

    # обработчики команд
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("chat", chat))
    application.add_handler(CommandHandler("code", code))
    application.add_handler(CommandHandler("report", report))
    application.add_handler(CommandHandler("pentest", pentest_menu))
    application.add_handler(CommandHandler("nikto", nikto_scan))
    application.add_handler(CommandHandler("sqlmap", sqlmap_scan))
    application.add_handler(CommandHandler("fetch", fetchpage))
    application.add_handler(CommandHandler("subdomains", subdomain_scan))
    application.add_handler(CommandHandler("ssrf", ssrf_scan))
    application.add_handler(CommandHandler("analyze", analyze))
    application.add_handler(CommandHandler("result", result))
    application.add_handler(CommandHandler("nuclei", nuclei_scan))
    application.add_handler(CommandHandler("waf", waf_check))

    application.add_handler(MessageHandler(filters.Document.TXT, handle_report_file))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, chat))  # Chat messages without command

    application.run_polling()


if __name__ == "__main__":
    main()
