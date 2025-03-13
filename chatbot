import asyncio
import subprocess
import requests
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, filters, MessageHandler
import openai
import traceback

# OpenAI API key
openai.api_key = "apikey"

# It stores last analysis
last_analysis = {}

# Asynchronous /start command
async def start(update, context):
    menu_text = (
        "*Hello! I am a bot for web penetration testing.*\n\n"
        "Here's what I can do:\n\n"
        "1. /chat - *Ask me any penetration testing questions!*\n"
        "2. /code - *Send me your code for vulnerability analysis.*\n"
        "3. /pentest - *Run penetration testing tools.*\n\n"
        "*Enter a command to get started!*"
    )
    await update.message.reply_text(menu_text, parse_mode='Markdown')

async def pentest_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    menu_text = (
        "*Pentesting Tools Menu:*\n\n"
        "1. /nikto <URL> - *Scan a website using Nikto for identifying common vulnerabilities and misconfigurations.*\n"
        "2. /sqlmap <URL> - *Scan a website using SQLMap for detecting SQL injection vulnerabilities.*\n"
        "3. /fetch <URL> - *Extract all links from a web page for analyzing the site structure and finding potential entry points.*\n"
        "4. /subdomains <URL> - *Search for subdomains for a website.*\n"
        "5. /ssrf <URL> - *Check a website for CSRF vulnerability.*\n"
        "6. /analyze - *Receive the analysis based on the results of the pentesting.*\n\n"
"*Enter a command to get started!!*"
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
            "*Vulnerability Summary:*\n\n"
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

#  scanning with Nikto
async def nikto_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = ' '.join(context.args)  # Get URL from command arguments
    if not url:
        await update.message.reply_text("Please provide a URL to scan with Nikto. Example: /nikto https://example.com")
        return

    try:
        await update.message.reply_text(f"Starting Nikto scan for {url}...")

        command = ["nikto", "-h", url]
        process = await asyncio.create_subprocess_exec(
            *command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        # Collect all output
        full_output = []
        while True:
            output = await process.stdout.readline()
            if output:
                output_text = output.decode().strip()
                full_output.append(output_text)
            else:
                break

        result_text = "\n".join(full_output)

        # Check stderr for errors
        stderr = await process.stderr.read()
        if stderr:
            stderr_text = stderr.decode().strip()
            if stderr_text:
                result_text += f"\n\nErrors:\n{stderr_text}"

        return_code = await process.wait()
        if return_code != 0:
            result_text += f"\n\nNikto exited with code {return_code}."

        # Send the result to the user
        if result_text:
            # Split the output if it exceeds Telegram's character limit (4096 characters)
            max_length = 4096
            for i in range(0, len(result_text), max_length):
                await update.message.reply_text(result_text[i:i + max_length])
        else:
            await update.message.reply_text("Nikto returned no results.")

        # Notification of completion
        await update.message.reply_text("Nikto scan completed. To start a new scan, send /nikto <URL>.")

    except Exception as e:
        await update.message.reply_text(f"An error occurred: {e}")

# Function for scanning with SQLMap
async def sqlmap_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = ' '.join(context.args)
    if not url:
        await update.message.reply_text("Please provide a URL to scan with SQLMap. Example: /sqlmap https://example.com")
        return

    try:
        await update.message.reply_text(f"Starting SQLMap scan for {url}...")

        command = ["sqlmap", "-u", url, "--batch"]
        process = await asyncio.create_subprocess_exec(
            *command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        # Collect all output
        full_output = []
        while True:
            output = await process.stdout.readline()
            if output:
                output_text = output.decode().strip()
                if output_text:
                    full_output.append(output_text)
            else:
                break

        # Save output to a file
        with open("sqlmap_output.txt", "w") as file:
            file.write("\n".join(full_output))

        # Send the file to the user
        with open("sqlmap_output.txt", "rb") as file:
            await update.message.reply_document(document=file, caption="SQLMap Scan Results")

        # Check stderr for errors
        stderr = await process.stderr.read()
        if stderr:
            stderr_text = stderr.decode().strip()
            if stderr_text:
                await update.message.reply_text(f"Error: {stderr_text}")

        # Check the return code
        return_code = await process.wait()
        if return_code != 0:
            await update.message.reply_text(f"SQLMap exited with code {return_code}.")

        # Notification of completion
        await update.message.reply_text("Scan completed. To start a new scan, send /sqlmap <URL>.")

    except Exception as e:
        await update.message.reply_text(f"An error occurred: {e}")

# Function for extracting all links from a web page
async def fetchpage(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = ' '.join(context.args)  # Get URL from command arguments
    if not url:
        await update.message.reply_text("Please provide a URL to extract links from. Example: /fetchpage https://example.com")
        return

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract all links (<a> tags) from the page
        links = soup.find_all('a', href=True)

        # If links are found, send them to the user
        if links:
            links_list = "\n".join([link['href'] for link in links])
            await update.message.reply_text(f"Found links on the page:\n{links_list}")
        else:
            await update.message.reply_text("No links found on the page.")
    except requests.exceptions.RequestException as e:
        await update.message.reply_text(f"An error occurred while fetching the page: {e}")

async def subdomain_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠ Specify the domain to search for subdomains. Example: /subdomains example.com")
        return

    domain = context.args[0]
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
    if not context.args:
        await update.message.reply_text(
            "⚠ Specify the URL with the parameter that can be tested. Example: /ssrf https://example.com/api?url=")
        return

    base_url = context.args[0]
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",  # AWS Instance Metadata Service
        "http://127.0.0.1:80",  # Local server
        "http://localhost:8080",  # Often used port
        "http://internal.example.com",  # Потенциальный внутренний домен
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
        await update.message.reply_text("✅ No CSRF vulnerabilities were found.")

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
    telegram_token = "token"
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

    application.add_handler(MessageHandler(filters.Document.TXT, handle_report_file))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, chat))  # Chat messages without command

    application.run_polling()


if __name__ == "__main__":
    main()
