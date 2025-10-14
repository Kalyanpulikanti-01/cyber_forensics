#!/usr/bin/env python3
"""
Screenshot Collector Module

This module provides screenshot collection capabilities using Selenium.

Owner: Samyama.ai - Vaidhyamegha Private Limited
Contact: madhulatha@samyama.ai
Website: https://Samyama.ai
License: Proprietary - All Rights Reserved
Version: 1.2.0
Last Updated: October 2025
"""

import asyncio
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import WebDriverException, TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

logger = logging.getLogger(__name__)


class ScreenshotCollector:
    """Screenshot collection and management using Selenium."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize screenshot collector with configuration."""
        self.config = config
        self.screenshot_dir = Path(self.config.get('screenshot_dir', 'screenshots'))
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        self.webdriver_path = self.config.get('webdriver_path')  # Optional: path to chromedriver
        self.wait_timeout = self.config.get('screenshot_timeout', 10)

    def _get_webdriver(self) -> webdriver.Chrome:
        """Initializes and returns a Selenium WebDriver instance."""
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36')

        service = Service(executable_path=self.webdriver_path) if self.webdriver_path else Service()

        try:
            return webdriver.Chrome(service=service, options=options)
        except WebDriverException as e:
            logger.error(f"Failed to initialize WebDriver. Ensure ChromeDriver is in your PATH or configured. Error: {e}")
            raise

    async def capture(self, url: str) -> Dict[str, Any]:
        """Capture a single, full-page screenshot of the URL."""
        result = {
            'url': url,
            'screenshot_path': None,
            'captured': False,
            'error': None
        }

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        filename = f"screenshot_{url_hash}_{timestamp}.png"
        screenshot_path = self.screenshot_dir / filename

        driver: Optional[webdriver.Chrome] = None
        try:
            driver = await asyncio.to_thread(self._get_webdriver)
            await asyncio.to_thread(driver.get, url)

            # Wait for the body element to be present, indicating page has loaded
            wait = WebDriverWait(driver, self.wait_timeout)
            await asyncio.to_thread(wait.until, EC.presence_of_element_located((By.TAG_NAME, 'body')))

            # Use JavaScript to get the full page height
            height = await asyncio.to_thread(driver.execute_script, "return document.body.scrollHeight")
            await asyncio.to_thread(driver.set_window_size, 1920, height if height > 1080 else 1080)
            await asyncio.sleep(0.5) # Small sleep to allow final rendering

            await asyncio.to_thread(driver.save_screenshot, str(screenshot_path))

            result['screenshot_path'] = str(screenshot_path)
            result['captured'] = True
            logger.info(f"Successfully captured screenshot of {url} to {screenshot_path}")

        except TimeoutException:
            error_message = f"Screenshot capture failed for {url}: Page load timed out after {self.wait_timeout} seconds."
            logger.error(error_message)
            result['error'] = error_message
        except Exception as e:
            error_message = f"Screenshot capture failed for {url}: {e}"
            logger.error(error_message)
            result['error'] = error_message
        finally:
            if driver:
                await asyncio.to_thread(driver.quit)
        
        return result
