import asyncio
import random
from playwright.async_api import async_playwright
from colorama import init, Fore, Style


async def get_final_response(page, last_seen_ids):
    """Wait until a new response finishes streaming and return it."""
    last_text = ""
    stable_count = 0

    while True:
        boxes = await page.query_selector_all("div.outputBox")
        if boxes:
            newest = boxes[-1]  # get the latest box
            box_id = await newest.get_attribute("id")

            if box_id and box_id not in last_seen_ids:
                text = await newest.inner_text()

                if text.strip() == last_text.strip():
                    stable_count += 1
                else:
                    stable_count = 0
                    last_text = text

                # when stable for 3 cycles (~3s) → done
                if stable_count >= 3 and text.strip():
                    last_seen_ids.add(box_id)
                    return text.strip()

        await asyncio.sleep(1)

def banner():
    print(Fore.YELLOW + "=" * 70)
    print(Fore.GREEN + "Welcome to Codex AI Automation CLI (Playwright)")
    print(Fore.YELLOW + "=" * 70)
    print(Fore.WHITE + "")

async def main():

    banner()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        await page.goto("https://deepai.org/chat", wait_until="domcontentloaded")
        await asyncio.sleep(random.uniform(2, 4))

        print("✅ Ready! Type your question (or 'exit' to quit).")

        seen_ids = set()

        while True:
            question = input("\n❓ Enter your question: ")
            if question.lower() in ["exit", "quit", "q"]:
                print("👋 Exiting...")
                break

            try:
                # Get fresh textarea
                chat_input = await page.wait_for_selector("#persistentChatbox", timeout=10000)
                await chat_input.click()
                await chat_input.fill(question)
                await asyncio.sleep(random.uniform(0.5, 1.2))

                # Click the send button
                send_btn = await page.wait_for_selector("#chatSubmitButton", timeout=5000)
                await send_btn.click()
            except Exception as e:
                print(f"⚠️ Could not send question: {e}")
                continue

            # Wait for the new response
            print("⏳ Waiting for AI response...")
            try:
                response = await get_final_response(page, seen_ids)
                print("\n=== DeepAI Response ===\n")
                print(response)
                print("\n=======================\n")
            except Exception as e:
                print(f"⚠️ Failed to get response: {e}")

        # keep browser alive
        print("Browser will stay open. Close it manually when done.")
        await asyncio.sleep(9999)

if __name__ == "__main__":
    asyncio.run(main())
