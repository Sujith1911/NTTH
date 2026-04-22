"""
Channel hopper — cycles the AR9271 monitor-mode interface through
WiFi channels 1–13 so the sniffer sees traffic on every channel.

Runs as a background asyncio task.  Gracefully handles interface
errors (e.g. adapter unplugged) without crashing the main loop.
"""
from __future__ import annotations

import asyncio
from typing import List

from app.core.logger import get_logger

log = get_logger("channel_hopper")

_running = False


async def start_channel_hopper(
    interface: str,
    channels: List[int] | None = None,
    hop_interval: float = 0.3,
) -> None:
    """
    Hop through *channels* on *interface* every *hop_interval* seconds.

    Parameters
    ----------
    interface : str
        Monitor-mode interface name, e.g. ``wlan0mon``.
    channels : list[int] | None
        Channel list to cycle through.  Defaults to 1–13 (2.4 GHz).
    hop_interval : float
        Seconds between hops.  0.3 s ≈ full sweep every 4 s.
    """
    global _running

    if channels is None:
        channels = list(range(1, 14))  # 2.4 GHz channels 1–13

    _running = True
    log.info(
        "channel_hopper.started",
        interface=interface,
        channels=channels,
        hop_interval=hop_interval,
    )

    idx = 0
    consecutive_errors = 0
    max_consecutive_errors = 10

    while _running:
        channel = channels[idx % len(channels)]
        try:
            proc = await asyncio.create_subprocess_exec(
                "iw", "dev", interface, "set", "channel", str(channel),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=2.0)

            if proc.returncode != 0:
                err_msg = stderr.decode().strip() if stderr else "unknown"
                # "Device or resource busy" is common during active capture — not fatal
                if "busy" not in err_msg.lower():
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        log.error(
                            "channel_hopper.too_many_errors",
                            interface=interface,
                            last_error=err_msg,
                        )
                        break
            else:
                consecutive_errors = 0

        except asyncio.TimeoutError:
            log.debug("channel_hopper.timeout", channel=channel)
        except FileNotFoundError:
            log.error("channel_hopper.iw_not_found", hint="Install iw: sudo apt install iw")
            break
        except Exception as exc:
            log.warning("channel_hopper.error", channel=channel, error=str(exc))
            consecutive_errors += 1
            if consecutive_errors >= max_consecutive_errors:
                break

        idx += 1
        await asyncio.sleep(hop_interval)

    _running = False
    log.info("channel_hopper.stopped", interface=interface)


def stop_channel_hopper() -> None:
    """Signal the hopper to stop on the next iteration."""
    global _running
    _running = False


def is_running() -> bool:
    return _running
