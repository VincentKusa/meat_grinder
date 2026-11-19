import asyncio
from pathlib import Path

from engine.base import BaseReconModule


class BrowserEvidence(BaseReconModule):
    def execute(self):
        print("[*] Capturing browser evidence of high-value findings...")

        findings = self.db.get_all_findings()
        target_urls = set()

        for f in findings:
            if f["severity"] in ["CRITICAL", "HIGH"]:
                url = f["url"].split(" -> ")[0]
                if url.startswith("http"):
                    target_urls.add(url)

        if not target_urls:
            print("[*] No high-severity HTTP endpoints found to capture.")
            return

        screenshot_dir = self.workspace / "screenshots"
        screenshot_dir.mkdir(exist_ok=True)

        # Run async browser capture
        asyncio.run(self._capture_screenshots(list(target_urls), screenshot_dir))

        print(f"[+] Browser evidence captured in {screenshot_dir}")

    async def _capture_screenshots(self, urls: list, output_dir: Path):
        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={"width": 1920, "height": 1080},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                )

                for i, url in enumerate(urls[:20]):  # Limit to 20 screenshots
                    try:
                        page = await context.new_page()
                        await page.goto(url, timeout=30000, wait_until="networkidle")

                        # Take screenshot
                        screenshot_path = output_dir / f"screenshot_{i+1}.png"
                        await page.screenshot(path=str(screenshot_path), full_page=False)

                        # Capture page title
                        title = await page.title()

                        # Log success
                        print(f"  ✓ Captured: {url} ({title})")

                        await page.close()

                    except Exception as e:
                        print(f"  ✗ Failed: {url} ({str(e)[:50]})")

                await browser.close()

        except ImportError:
            print("[!] Playwright not installed. Run: pip install playwright && playwright install chromium")
        except Exception as e:
            print(f"[!] Browser evidence capture failed: {e}")
