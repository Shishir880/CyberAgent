"""
CyberAgent Date & Time Calculation Toolset
=========================================
Provides comprehensive date, time, duration, and expiration calculation capabilities:
- Current local time, UTC time, Unix epoch timestamps, ISO 8601 formatting
- Date & time arithmetic: adding/subtracting days, weeks, hours, minutes, seconds
- Precise time differences (deltas) between two dates or timestamps
- Timestamp conversion (Unix epoch <-> human readable date strings)
- Expiration analysis (SSL certificate, JWT token expiry, session age)
"""

import time
import datetime
from typing import Dict, Any, Optional


class DateTimeToolsMixin:
    """Mixin implementing versatile date, time, duration, and arithmetic calculations."""

    def calculate_datetime(
        self,
        action: str = "now",
        base_date: Optional[str] = None,
        target_date: Optional[str] = None,
        days: int = 0,
        hours: int = 0,
        minutes: int = 0,
        seconds: int = 0,
        timestamp: Optional[float] = None,
        date_format: str = "%Y-%m-%d %H:%M:%S"
    ) -> Dict[str, Any]:
        """
        Performs precise date, time, duration, arithmetic, and expiration calculations.

        Supported actions:
        - 'now': Returns current local time, UTC time, timezone, epoch timestamp, and ISO format.
        - 'add': Adds specified days, hours, minutes, seconds to base_date (or current time).
        - 'subtract': Subtracts specified days, hours, minutes, seconds from base_date (or current time).
        - 'diff': Calculates duration between base_date and target_date (in days, hours, minutes, seconds).
        - 'convert': Converts between Unix epoch timestamp and readable date string.
        - 'expiry_check': Evaluates if target_date has expired or how many days/hours remain.
        """
        action = action.lower().strip()
        now_local = datetime.datetime.now()
        now_utc = datetime.datetime.now(datetime.timezone.utc)

        def parse_date(date_str: Optional[str]) -> datetime.datetime:
            if not date_str:
                return now_local
            date_str = date_str.strip()
            # Try ISO formats and standard formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d",
                "%d-%m-%Y %H:%M:%S",
                "%d/%m/%Y %H:%M:%S",
                "%d/%m/%Y",
                "%d-%m-%Y",
                "%b %d %Y",
                "%B %d, %Y"
            ]
            for fmt in formats:
                try:
                    return datetime.datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
            # Try float/int timestamp string
            try:
                epoch = float(date_str)
                return datetime.datetime.fromtimestamp(epoch)
            except ValueError:
                pass
            raise ValueError(f"Unable to parse date string '{date_str}'. Supported formats include YYYY-MM-DD HH:MM:SS, YYYY-MM-DD, or Unix timestamp.")

        try:
            if action in ("now", "current"):
                tz_name = time.tzname[time.daylight] if time.daylight else time.tzname[0]
                return {
                    "success": True,
                    "action": "now",
                    "local_datetime": now_local.strftime(date_format),
                    "utc_datetime": now_utc.strftime(date_format),
                    "iso_8601": now_local.isoformat(),
                    "unix_timestamp": round(time.time(), 3),
                    "day_of_week": now_local.strftime("%A"),
                    "timezone": tz_name,
                    "formatted": {
                        "date": now_local.strftime("%Y-%m-%d"),
                        "time_24h": now_local.strftime("%H:%M:%S"),
                        "time_12h": now_local.strftime("%I:%M:%S %p"),
                        "year": now_local.year,
                        "month": now_local.strftime("%B"),
                        "day": now_local.day
                    }
                }

            elif action in ("add", "plus"):
                base_dt = parse_date(base_date)
                delta = datetime.timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
                result_dt = base_dt + delta
                return {
                    "success": True,
                    "action": "add",
                    "base_date": base_dt.strftime(date_format),
                    "offset_applied": {
                        "days": days,
                        "hours": hours,
                        "minutes": minutes,
                        "seconds": seconds
                    },
                    "result_datetime": result_dt.strftime(date_format),
                    "result_iso": result_dt.isoformat(),
                    "result_timestamp": result_dt.timestamp(),
                    "day_of_week": result_dt.strftime("%A")
                }

            elif action in ("subtract", "minus"):
                base_dt = parse_date(base_date)
                delta = datetime.timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
                result_dt = base_dt - delta
                return {
                    "success": True,
                    "action": "subtract",
                    "base_date": base_dt.strftime(date_format),
                    "offset_subtracted": {
                        "days": days,
                        "hours": hours,
                        "minutes": minutes,
                        "seconds": seconds
                    },
                    "result_datetime": result_dt.strftime(date_format),
                    "result_iso": result_dt.isoformat(),
                    "result_timestamp": result_dt.timestamp(),
                    "day_of_week": result_dt.strftime("%A")
                }

            elif action in ("diff", "difference", "duration"):
                if not base_date or not target_date:
                    return {"success": False, "error": "Both 'base_date' and 'target_date' are required for action='diff'."}
                dt1 = parse_date(base_date)
                dt2 = parse_date(target_date)
                delta = dt2 - dt1
                total_seconds = delta.total_seconds()
                is_future = total_seconds >= 0
                abs_sec = abs(total_seconds)

                total_days = int(abs_sec // 86400)
                rem_sec = abs_sec % 86400
                total_hours = int(rem_sec // 3600)
                rem_sec %= 3600
                total_mins = int(rem_sec // 60)
                total_secs = int(rem_sec % 60)

                human_parts = []
                if total_days > 0: human_parts.append(f"{total_days} days")
                if total_hours > 0: human_parts.append(f"{total_hours} hours")
                if total_mins > 0: human_parts.append(f"{total_mins} mins")
                if total_secs > 0 or not human_parts: human_parts.append(f"{total_secs} secs")
                human_str = ", ".join(human_parts)
                if not is_future:
                    human_str += " in the past"

                return {
                    "success": True,
                    "action": "diff",
                    "start_date": dt1.strftime(date_format),
                    "end_date": dt2.strftime(date_format),
                    "total_seconds": total_seconds,
                    "total_days": round(total_seconds / 86400, 2),
                    "total_hours": round(total_seconds / 3600, 2),
                    "duration_breakdown": {
                        "days": total_days if is_future else -total_days,
                        "hours": total_hours,
                        "minutes": total_mins,
                        "seconds": total_secs
                    },
                    "human_readable": human_str,
                    "is_target_in_future": is_future
                }

            elif action in ("convert", "timestamp"):
                if timestamp is not None:
                    conv_dt = datetime.datetime.fromtimestamp(timestamp)
                    return {
                        "success": True,
                        "action": "convert",
                        "input_timestamp": timestamp,
                        "datetime": conv_dt.strftime(date_format),
                        "iso_8601": conv_dt.isoformat(),
                        "day_of_week": conv_dt.strftime("%A")
                    }
                elif base_date:
                    conv_dt = parse_date(base_date)
                    return {
                        "success": True,
                        "action": "convert",
                        "input_date": base_date,
                        "unix_timestamp": conv_dt.timestamp(),
                        "iso_8601": conv_dt.isoformat(),
                        "formatted": conv_dt.strftime(date_format),
                        "day_of_week": conv_dt.strftime("%A")
                    }
                else:
                    return {"success": False, "error": "Provide either 'timestamp' or 'base_date' to convert."}

            elif action in ("expiry_check", "expires", "validity"):
                check_dt = parse_date(target_date or base_date)
                delta = check_dt - now_local
                total_seconds = delta.total_seconds()
                is_expired = total_seconds <= 0

                abs_sec = abs(total_seconds)
                days_val = int(abs_sec // 86400)
                hours_val = int((abs_sec % 86400) // 3600)
                mins_val = int((abs_sec % 3600) // 60)

                status = "EXPIRED" if is_expired else "ACTIVE"
                if is_expired:
                    summary = f"Expired {days_val} days and {hours_val} hours ago"
                else:
                    summary = f"Valid for {days_val} days, {hours_val} hours, {mins_val} minutes remaining"

                return {
                    "success": True,
                    "action": "expiry_check",
                    "target_datetime": check_dt.strftime(date_format),
                    "current_datetime": now_local.strftime(date_format),
                    "status": status,
                    "is_expired": is_expired,
                    "seconds_remaining": total_seconds if not is_expired else 0,
                    "days_remaining": round(total_seconds / 86400, 2) if not is_expired else 0,
                    "time_summary": summary
                }

            else:
                return {
                    "success": False,
                    "error": f"Unknown action '{action}'. Supported actions: 'now', 'add', 'subtract', 'diff', 'convert', 'expiry_check'."
                }

        except Exception as ex:
            return {"success": False, "error": str(ex)}
