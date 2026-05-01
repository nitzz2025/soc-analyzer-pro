import aiohttp
import asyncio
import logging

async def send_webhook_alert(url: str, payload: dict):
    if not url: return
    timeout = aiohttp.ClientTimeout(total=5)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload) as response:
                if response.status != 200: logging.error(f"Webhook failed: {response.status}")
    except Exception as e: logging.error(f"Alert Error: {e}")