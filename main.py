import os
import sys
import enum
import math
import shutil
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Any, Awaitable, Callable, Dict

import httpx
from pyrogram import Client, errors as pyrogram_errors
from pyrogram.raw import functions as pyrogram_functions
from dotenv import load_dotenv
from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, Enum, Boolean, BigInteger, text, select, func, or_, cast, delete, update
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

from aiogram import Bot, Dispatcher, Router, BaseMiddleware
from aiogram.filters import CommandStart, Command
from aiogram.types import (
    Message, CallbackQuery, Update, TelegramObject, User as TGUser,
    InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo,
    BotCommandScopeChat, BotCommandScopeAllPrivateChats, MenuButtonWebApp
)
from uvicorn import Config, Server
import aiohttp
import re
import json
import string
import random
import time
import requests
import pycountry
import phonenumbers
import urllib.request
import urllib.parse
import hashlib
import hmac
import traceback
from urllib.parse import parse_qsl
from pydantic import BaseModel
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

# ==============================================================================
# 🔹 SECTION 0: SESSION MANAGER (Pyrogram-based Telegram Login)
# ==============================================================================

# Temporary store of active Pyrogram clients during sign-in flow
_login_clients: Dict[int, Client] = {}

async def _create_pyrogram_client(session_string: str = None) -> Client:
    identity = {
        "device_model": "Samsung SM-S918B",
        "system_version": "Android 14",
        "app_version": "10.14.5",
        "lang_code": "en"
    }
    # API_ID/API_HASH are resolved after load_dotenv() - use lazy references
    _api_id = int(os.getenv("API_ID", "32796500"))
    _api_hash = os.getenv("API_HASH", "1675896d79afbe13f67af7919ee06489").strip()
    if session_string:
        return Client(name="temp", api_id=_api_id, api_hash=_api_hash, session_string=session_string, in_memory=True, **identity)
    return Client(name="temp", api_id=_api_id, api_hash=_api_hash, in_memory=True, **identity)

async def request_app_code(user_id: int, phone_number: str) -> str:
    """Sends verification code and returns phone_code_hash."""
    client = await _create_pyrogram_client()
    await client.connect()
    await asyncio.sleep(1.5)
    try:
        sent_code = await client.send_code(phone_number)
        _login_clients[user_id] = client
        return sent_code.phone_code_hash
    except pyrogram_errors.PhoneNumberBanned:
        raise Exception("Phone number is banned on Telegram.")
    except pyrogram_errors.PhoneNumberInvalid:
        raise Exception("PHONE_NUMBER_INVALID")
    except Exception as e:
        if client.is_connected:
            await client.disconnect()
        raise e

async def submit_app_code(user_id: int, phone_number: str, phone_code_hash: str, phone_code: str, password: str = None) -> dict | None:
    """Submits OTP (and optional 2FA password) - returns session_string or need_2fa signal."""
    client = _login_clients.get(user_id)
    if not client:
        logging.error(f"Submit OTP: No active client for user {user_id} (server may have restarted).")
        return None
    try:
        await asyncio.sleep(random.uniform(1.5, 3.0))
        try:
            await client.sign_in(phone_number, phone_code_hash, phone_code)
        except pyrogram_errors.SessionPasswordNeeded:
            # 2FA required - if password provided, use it; otherwise signal frontend
            if password:
                await client.check_password(password)
            else:
                # Keep client alive in _login_clients so 2FA can be submitted later
                return {"status": "need_2fa"}

        temp_session = await client.export_session_string()
        try:
            await client.disconnect()
        except: pass

        client = await _create_pyrogram_client(temp_session)
        await client.connect()
        session_string = temp_session

        # Check if account already has 2FA enabled
        already_has_2fa = False
        try:
            from pyrogram.raw.functions.account import GetPassword as GetPasswordRaw
            password_info = await client.invoke(GetPasswordRaw())
            already_has_2fa = password_info.has_password
        except Exception as e:
            logging.warning(f"Could not check 2FA status for {phone_number}: {e}")

        if already_has_2fa:
            # Account already has 2FA — keep the password the user entered (or None if not entered)
            two_fa_password = password if password else None
            logging.info(f"2FA already enabled for {phone_number}, keeping existing password.")
        else:
            # No 2FA — generate a random one and enable it
            two_fa_password = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
            try:
                await client.enable_cloud_password(two_fa_password)
                logging.info(f"2FA enabled for {phone_number} with generated password.")
            except Exception as e:
                logging.warning(f"2FA enable failed for {phone_number}: {e}")
                two_fa_password = None

        has_other_sessions = False
        try:
            from pyrogram.raw.functions.account import GetAuthorizations
            result = await client.invoke(GetAuthorizations())
            if len(result.authorizations) > 1:
                has_other_sessions = True
        except Exception as e:
            logging.warning(f"GetAuthorizations failed: {e}")

        return {
            "status": "success",
            "session_string": session_string,
            "two_fa_password": two_fa_password,
            "has_other_sessions": has_other_sessions
        }
    except pyrogram_errors.PhoneCodeInvalid:
        raise Exception("Invalid verification code. Please try again.")
    except pyrogram_errors.PhoneCodeExpired:
        raise Exception("Verification code expired. Please request a new one.")
    except pyrogram_errors.PasswordHashInvalid:
        raise Exception("Invalid 2FA password. Please try again.")
    except Exception as e:
        raise e
    finally:
        # Only pop client if login fully completed (or errored)
        if _login_clients.get(user_id) and _login_clients[user_id].is_connected:
            try:
                if _login_clients[user_id] != client:
                    await _login_clients[user_id].disconnect()
            except: pass
        # Don't pop if need_2fa - we keep client for second attempt
        pass

async def get_telegram_login_code(session_string: str, after_ts: float = None) -> str | None:
    client = await _create_pyrogram_client(session_string)
    code = None
    now = time.time()
    try:
        await client.connect()
        async for message in client.get_chat_history(777000, limit=5):
            msg_ts = message.date.timestamp() if message.date else 0
            if after_ts and msg_ts < after_ts:
                continue
            if not after_ts and (now - msg_ts) > 120:
                continue
            text_msg = message.text
            if not text_msg:
                continue
            match = re.search(r'\b(\d{5})\b', text_msg)
            if match:
                code = match.group(1)
                break
    except (pyrogram_errors.AuthKeyInvalid, pyrogram_errors.AuthKeyUnregistered,
            pyrogram_errors.UserDeactivated, pyrogram_errors.SessionRevoked):
        raise Exception("SESSION_REVOKED")
    except Exception as e:
        logging.error(f"Error fetching code: {e}")
        raise e
    finally:
        if client.is_connected:
            await client.disconnect()
    return code

async def clean_account_for_buyer(session_string: str, two_fa: str = None):
    try:
        client = await _create_pyrogram_client(session_string)
        await client.connect()
        try:
            await client.invoke(pyrogram_functions.auth.ResetAuthorizations())
        except pyrogram_errors.FreshResetAuthorisationForbidden:
            try:
                auths = await client.invoke(pyrogram_functions.account.GetAuthorizations())
                for auth in auths.authorizations:
                    if auth.hash != 0:
                        try:
                            await client.invoke(pyrogram_functions.account.TerminateAuthorization(hash=auth.hash))
                        except: pass
            except: pass
        except Exception as e:
            logging.error(f"ResetAuthorizations failed: {e}")
        try:
            if two_fa and two_fa.strip():
                await client.remove_cloud_password(two_fa)
        except Exception as e:
            logging.error(f"Remove 2FA failed: {e}")
        if client.is_connected:
            await client.disconnect()
    except Exception as e:
        logging.error(f"clean_account_for_buyer error: {e}")

async def logout_bot_session(session_string: str, delay: int = 600):
    if not session_string: return
    try:
        client = await _create_pyrogram_client(session_string)
        await client.connect()
        try:
            initial_auths = await client.invoke(pyrogram_functions.account.GetAuthorizations())
            initial_count = len(initial_auths.authorizations)
        except:
            initial_count = 1
        start_time = asyncio.get_event_loop().time()
        while (asyncio.get_event_loop().time() - start_time) < delay:
            await asyncio.sleep(5)
            try:
                current_auths = await client.invoke(pyrogram_functions.account.GetAuthorizations())
                if len(current_auths.authorizations) > initial_count:
                    break
            except:
                return
        await client.log_out()
    except Exception as e:
        logging.error(f"logout_bot_session error: {e}")

async def is_session_alive(session_string: str) -> tuple[bool, str]:
    try:
        client = await _create_pyrogram_client(session_string)
        await client.connect()
        me = await client.get_me()
        if not me or getattr(me, 'is_scam', False) or getattr(me, 'is_fake', False):
            return False, "frozen"
        try:
            test_msg = await client.send_message("me", "✅")
            await test_msg.delete()
        except:
            return False, "frozen"
        try:
            import time as _time
            start_time = _time.time()
            await client.send_message("SpamBot", "/start")
            spambot_replied = False
            for i in range(15):
                await asyncio.sleep(0.5)
                async for msg in client.get_chat_history("SpamBot", limit=3):
                    if msg.from_user and msg.from_user.id == 178220800 and msg.date.timestamp() > (start_time - 2):
                        spambot_replied = True
                        btn_count = 0
                        markup = getattr(msg, "reply_markup", None)
                        if markup:
                            if hasattr(markup, "inline_keyboard"):
                                for row in markup.inline_keyboard:
                                    btn_count += len(row)
                            if hasattr(markup, "keyboard"):
                                for row in markup.keyboard:
                                    btn_count += len(row)
                        if btn_count >= 3:
                            return False, "spam"
                        return True, ""
                if spambot_replied:
                    break
            if not spambot_replied:
                return False, "spam_no_reply"
        except Exception as e:
            err_type = type(e).__name__
            if any(x in err_type for x in ["PeerFlood", "UserRestricted", "Forbidden"]):
                return False, "spam"
            return False, f"check_failed: {err_type}"
        return True, ""
    except Exception as e:
        err_str = str(e).lower()
        if any(k in err_str for k in ["unauthorized", "auth", "session"]):
            return False, "session_removed"
        return False, "frozen"
    finally:
        try:
            if 'client' in locals() and client.is_connected:
                await client.disconnect()
        except: pass


# ==============================================================================
# 🔹 SECTION 1: CONFIGURATION (إعدادات النظام والمشروع)
# ==============================================================================

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "8910893791:AAEMjc4ePILB68ICpOH4hi-bTEM7wpNlvAk").strip()
API_ID_RAW = os.getenv("API_ID", "32796500")
API_ID = int(API_ID_RAW) if str(API_ID_RAW).isdigit() else 32796500
API_HASH = os.getenv("API_HASH", "1675896d79afbe13f67af7919ee06489").strip()

ADMIN_IDS_RAW = os.getenv("ADMIN_IDS", "8526602181").strip()
ADMIN_IDS = [int(x.strip()) for x in ADMIN_IDS_RAW.split(",") if x.strip().isdigit()]
if not ADMIN_IDS:
    ADMIN_IDS = [8526602181]

STORE_ADMIN_IDS = ADMIN_IDS.copy()
SELLER_BOT_TOKEN = BOT_TOKEN  # Alias for backward compatibility

# Database Path
if os.path.exists("/app/data"):
    DATABASE_URL = "sqlite+aiosqlite:////app/data/app.db"
elif os.path.exists("/data"):
    DATABASE_URL = "sqlite+aiosqlite:////data/app.db"
else:
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///app.db")

# WebApp URLs
WEBAPP_URL = os.getenv("WEBAPP_URL", os.getenv("WEB_URL", "https://tg-test-plus3414-production.up.railway.app")).rstrip("/")
STORE_URL = f"{WEBAPP_URL}/store?v=3"

# Binance Payment Config
BINANCE_API_KEY = os.getenv("BINANCE_API_KEY", "")
BINANCE_API_SECRET = os.getenv("BINANCE_API_SECRET", "")
DEPOSIT_ADDRESS = os.getenv("DEPOSIT_ADDRESS", "")


# ==============================================================================
# 🔹 SECTION 2: DATABASE & ORM MODELS (قاعدة البيانات والنماذج)
# ==============================================================================

if os.path.exists("/data") and not os.path.exists("/data/app.db"):
    if os.path.exists("app.db"):
        try:
            shutil.copy2("app.db", "/data/app.db")
            print("Successfully migrated app.db to /data/app.db")
        except Exception as e:
            print(f"Migration failed: {e}")

Base = declarative_base()

class AccountStatus(enum.Enum):
    AVAILABLE = "available"
    PENDING = "pending"
    SOLD = "sold"
    REJECTED = "rejected"
    
class WithdrawalStatus(enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

class TransactionType(enum.Enum):
    DEPOSIT = "deposit"
    BUY = "buy"
    SELL = "sell"
    WITHDRAW = "withdraw"
    REFERRAL = "referral"

class User(Base):
    __tablename__ = 'users'
    id = Column(BigInteger, primary_key=True) # Telegram User ID
    balance_store = Column(Float, default=0.0)
    balance_sourcing = Column(Float, default=0.0)
    language = Column(String, default="ar")
    join_date = Column(DateTime, default=datetime.utcnow)
    full_name = Column(String, nullable=True)
    username = Column(String, nullable=True)
     
    # Isolation flags
    is_active_store = Column(Boolean, default=False)
    is_active_sourcing = Column(Boolean, default=False)
    is_banned_store = Column(Boolean, default=False)
    is_banned_sourcing = Column(Boolean, default=False)
    
    # Referral System
    referred_by = Column(BigInteger, ForeignKey('users.id'), nullable=True)
    refer_count = Column(Integer, default=0)
    referral_earnings = Column(Float, default=0.0)
    referral_bonus_awarded = Column(Boolean, default=False)

class Account(Base):
    __tablename__ = 'accounts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    phone_number = Column(String, unique=True, nullable=False)
    country = Column(String, nullable=False)
    session_string = Column(String, nullable=True)
    status = Column(Enum(AccountStatus), default=AccountStatus.AVAILABLE)
    price = Column(Float, nullable=False)
    seller_id = Column(BigInteger, ForeignKey('users.id'), nullable=True)
    buyer_id = Column(BigInteger, ForeignKey('users.id'), nullable=True)
    otp_code = Column(String, nullable=True)
    two_fa_password = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    purchased_at = Column(DateTime, nullable=True)
    locked_buy_price = Column(Float, nullable=True)
    locked_approve_delay = Column(Integer, nullable=True)
    reject_reason = Column(String, nullable=True)
    server_id = Column(Integer, ForeignKey('api_servers.id'), nullable=True)
    hash_code = Column(String, nullable=True)
    withdrawal_id = Column(Integer, ForeignKey('withdrawal_requests.id'), nullable=True)

class Transaction(Base):
    __tablename__ = 'transactions'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, ForeignKey('users.id'), nullable=False)
    type = Column(Enum(TransactionType), nullable=False)
    amount = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

class CountryPrice(Base):
    __tablename__ = 'country_prices'
    id = Column(Integer, primary_key=True, autoincrement=True)
    country_code = Column(String, nullable=False)
    iso_code = Column(String, default="XX")
    country_name = Column(String, nullable=False)
    price = Column(Float, nullable=False, default=1.0)
    buy_price = Column(Float, nullable=False, default=0.5)
    approve_delay = Column(Integer, nullable=False, default=0)
    log_quantity = Column(Integer, nullable=False, default=1000)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class UserCountryPrice(Base):
    __tablename__ = 'user_country_prices'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False)
    country_code = Column(String, nullable=False)
    iso_code = Column(String, default="XX")
    buy_price = Column(Float, nullable=False)
    approve_delay = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

class UserStorePrice(Base):
    __tablename__ = 'user_store_prices'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False)
    country_code = Column(String, nullable=False)
    iso_code = Column(String, default="XX")
    sell_price = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class WithdrawalRequest(Base):
    __tablename__ = 'withdrawal_requests'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, ForeignKey('users.id'), nullable=False)
    amount = Column(Float, nullable=False)
    method = Column(String, nullable=False)
    address = Column(String, nullable=False)
    fee = Column(Float, nullable=False, default=0.0)
    net_amount = Column(Float, nullable=False, default=0.0)
    transaction_id = Column(String(12), unique=True, nullable=True)
    status = Column(Enum(WithdrawalStatus), default=WithdrawalStatus.PENDING)
    created_at = Column(DateTime, default=datetime.utcnow)

class Deposit(Base):
    __tablename__ = 'deposits'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, ForeignKey('users.id'), nullable=False)
    amount = Column(Float, nullable=False)
    txid = Column(String, unique=True, nullable=False)
    method = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class AppSetting(Base):
    __tablename__ = 'app_settings'
    key = Column(String, primary_key=True)
    value = Column(String, nullable=True)

class ApiServer(Base):
    __tablename__ = 'api_servers'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    api_key = Column(String, nullable=False)
    server_type = Column(String, default="standard")
    extra_id = Column(String, nullable=True)
    profit_margin = Column(Float, default=20.0)
    min_profit = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SubscriptionChannel(Base):
    __tablename__ = 'subscription_channels'
    id = Column(Integer, primary_key=True, autoincrement=True)
    bot_type = Column(String, default="store")
    username = Column(String, nullable=False)
    link = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# Engine setup
engine = create_async_engine(DATABASE_URL, echo=False)
async_session = sessionmaker(
    engine, expire_on_commit=False, class_=AsyncSession
)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        try:
            def check_withdraw_cols(connection):
                cursor = connection.execute(text("PRAGMA table_info(withdrawal_requests)"))
                return [row[1] for row in cursor]
            
            w_cols = await conn.run_sync(check_withdraw_cols)
            if 'transaction_id' not in w_cols:
                await conn.execute(text("ALTER TABLE withdrawal_requests ADD COLUMN transaction_id VARCHAR(12)"))
            
            def check_deposit_cols(connection):
                cursor = connection.execute(text("PRAGMA table_info(deposits)"))
                return [row[1] for row in cursor]
            
            d_cols = await conn.run_sync(check_deposit_cols)
            if 'method' not in d_cols:
                await conn.execute(text("ALTER TABLE deposits ADD COLUMN method VARCHAR(50)"))

            def check_account_cols(connection):
                cursor = connection.execute(text("PRAGMA table_info(accounts)"))
                return [row[1] for row in cursor]
            
            a_cols = await conn.run_sync(check_account_cols)
            if 'server_id' not in a_cols:
                await conn.execute(text("ALTER TABLE accounts ADD COLUMN server_id INTEGER"))
            if 'hash_code' not in a_cols:
                await conn.execute(text("ALTER TABLE accounts ADD COLUMN hash_code TEXT"))

            def check_srv_cols(connection):
                cursor = connection.execute(text("PRAGMA table_info(api_servers)"))
                return [row[1] for row in cursor]
            
            s_cols = await conn.run_sync(check_srv_cols)
            if 'server_type' not in s_cols:
                await conn.execute(text("ALTER TABLE api_servers ADD COLUMN server_type VARCHAR(20) DEFAULT 'standard'"))
            if 'extra_id' not in s_cols:
                await conn.execute(text("ALTER TABLE api_servers ADD COLUMN extra_id VARCHAR(100)"))

            def check_cp_cols(connection):
                cursor = connection.execute(text("PRAGMA table_info(country_prices)"))
                return [row[1] for row in cursor]
            
            cp_cols = await conn.run_sync(check_cp_cols)
            if 'log_quantity' not in cp_cols:
                await conn.execute(text("ALTER TABLE country_prices ADD COLUMN log_quantity INTEGER DEFAULT 1000"))

            def check_sub_cols(connection):
                cursor = connection.execute(text("PRAGMA table_info(subscription_channels)"))
                return [row[1] for row in cursor]
            
            try:
                sub_cols = await conn.run_sync(check_sub_cols)
                if 'bot_type' not in sub_cols:
                    await conn.execute(text("ALTER TABLE subscription_channels ADD COLUMN bot_type VARCHAR DEFAULT 'store'"))
            except Exception:
                pass

            def check_user_cols(connection):
                cursor = connection.execute(text("PRAGMA table_info(users)"))
                return [row[1] for row in cursor]
            
            try:
                u_cols = await conn.run_sync(check_user_cols)
                if 'refer_count' not in u_cols:
                    await conn.execute(text("ALTER TABLE users ADD COLUMN refer_count INTEGER DEFAULT 0"))
                if 'referral_bonus_awarded' not in u_cols:
                    await conn.execute(text("ALTER TABLE users ADD COLUMN referral_bonus_awarded BOOLEAN DEFAULT 0"))
            except Exception:
                pass
                
        except Exception as e:
            print(f"Migration check warning: {e}")


# ==============================================================================
# 🔹 SECTION 3: SERVICES & PROVIDER API (الخدمات والربط مع المزودين)
# ==============================================================================

logger = logging.getLogger(__name__)

class ExternalProvider:
    def __init__(self, name, url, api_key, profit_margin, min_profit=0.0, server_type="standard", extra_id=None):
        self.name = name
        self.url = url.rstrip('/') + '/'
        self.api_key = api_key
        self.profit_margin = profit_margin
        self.min_profit = min_profit
        self.server_type = server_type
        self.extra_id = extra_id

    def get_base_params(self, action):
        if self.server_type == "lion":
            return {
                "action": action,
                "apiKey": self.api_key,
                "YourID": self.extra_id
            }
        else:
            return {
                "action": action,
                "apiKey": self.api_key,
                "apiKay": self.api_key
            }

    async def get_countries(self):
        try:
            async with httpx.AsyncClient() as client:
                action = "country_info" if self.server_type == "lion" else "getCountrys"
                params = self.get_base_params(action)
                resp = await client.get(self.url, params=params, timeout=15.0)
                if resp.status_code == 200:
                    return resp.json()
                return []
        except Exception as e:
            logger.error(f"Error fetching countries from {self.name}: {e}")
            return []

    async def get_balance(self):
        try:
            async with httpx.AsyncClient() as client:
                action = "get_balance" if self.server_type == "lion" else "getBalance"
                params = self.get_base_params(action)
                resp = await client.get(self.url, params=params, timeout=15.0)
                if resp.status_code == 200:
                    text_data = resp.text.strip()
                    try:
                        data = resp.json()
                        if isinstance(data, dict):
                            balance_keys = ["wallet", "balance", "Balance", "money", "credit", "amount", "balans", "sum", "user_balance", "available_balance", "credits"]
                            def parse_numeric(v):
                                if v is None: return None
                                if isinstance(v, (int, float)): return float(v)
                                try: return float(v)
                                except:
                                    try: return float(str(v).lower().replace('usd', '').replace('$', '').replace('€', '').replace('₽', '').strip().split()[0])
                                    except: return None

                            for key in balance_keys:
                                if key in data and data[key] is not None:
                                    val = parse_numeric(data[key])
                                    if val is not None: return {"status": "success", "balance": val}
                            
                            for sub in ['result', 'user', 'info', 'data']:
                                if sub in data:
                                    if isinstance(data[sub], dict):
                                        for key in balance_keys:
                                            v = data[sub].get(key)
                                            if v is not None:
                                                val = parse_numeric(v)
                                                if val is not None: return {"status": "success", "balance": val}
                                    elif sub == 'result':
                                        val = parse_numeric(data[sub])
                                        if val is not None: return {"status": "success", "balance": val}

                            msg = data.get("message") or data.get("msg") or data.get("error") or data.get("status")
                            if msg and msg not in ["success", "ok", True]:
                                return {"status": "error", "message": f"{msg}"}
                            return {"status": "error", "message": "Balance key missing"}
                    except Exception:
                        pass
                    
                    try:
                        first_word = text_data.lower().replace('usd', '').replace('$', '').strip().split()[0]
                        return {"status": "success", "balance": float(first_word)}
                    except Exception:
                        pass
                            
                    return {"status": "error", "message": f"Format Error. Text: {text_data[:50]}"}
                return {"status": "error", "message": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def buy_number(self, country_code):
        try:
            async with httpx.AsyncClient() as client:
                params = self.get_base_params("getNumber")
                if self.server_type == "lion":
                    params["country_code"] = country_code
                else:
                    params["country"] = country_code
                    params["service"] = "ot"
                
                resp = await client.get(self.url, params=params, timeout=20.0)
                if resp.status_code == 200:
                    text_data = resp.text.strip()
                    try:
                        data = resp.json()
                        if isinstance(data, dict):
                            res_node = data.get("result") if isinstance(data.get("result"), dict) else data
                            if data.get("status") == "success" or data.get("ok") is True:
                                res = {
                                    "status": "success",
                                    "number": res_node.get("number") or res_node.get("phone") or data.get("number"),
                                    "id": res_node.get("id") or res_node.get("id_activation") or res_node.get("hash_code") or data.get("id"),
                                    "hash_code": res_node.get("hash_code") or res_node.get("id") or res_node.get("id_activation") or data.get("hash_code")
                                }
                                if res["number"] and res["id"]:
                                    return res
                    except Exception:
                        pass
                    
                    if "ACCESS_NUMBER" in text_data:
                        parts = text_data.split(':')
                        if len(parts) >= 3:
                            return {
                                "status": "success",
                                "id": parts[1],
                                "hash_code": parts[1],
                                "number": parts[2]
                            }
                    
                    msg_lower = text_data.lower()
                    if any(err in msg_lower for err in ["no_numbers", "no_number", "out_of_stock"]):
                        return {"status": "error", "message": "No numbers available"}
                    if any(err in msg_lower for err in ["no_balance", "no_money", "insufficient"]):
                        return {"status": "error", "message": "No balance in API provider"}
                    return {"status": "error", "message": text_data}
                return {"status": "error", "message": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def get_code(self, hash_code, number=None):
        try:
            async with httpx.AsyncClient() as client:
                action = "getCode"
                params = self.get_base_params(action)
                if self.server_type == "lion":
                    params["number"] = number
                else:
                    params["hash_code"] = hash_code
                    params["id"] = hash_code
                
                resp = await client.get(self.url, params=params, timeout=15.0)
                if resp.status_code == 200:
                    text_data = resp.text.strip()
                    try:
                        data = resp.json()
                        if isinstance(data, dict):
                            res_node = data.get("result") if isinstance(data.get("result"), dict) else data
                            if (data.get("status") == "success" or data.get("ok") is True) and (res_node.get("code") or res_node.get("otp")):
                                return {"status": "success", "code": res_node.get("code") or res_node.get("otp")}
                            code = res_node.get("code") or res_node.get("otp") or res_node.get("sms") or data.get("code")
                            if code:
                                return {"status": "success", "code": code}
                    except Exception:
                        pass
                    
                    if "STATUS_OK" in text_data:
                        parts = text_data.split(':')
                        if len(parts) >= 2:
                            return {"status": "success", "code": parts[1]}
                    
                    if "STATUS_WAIT" in text_data:
                        return {"status": "error", "message": "Code not arrived yet"}
                        
                    if text_data and len(text_data) <= 10 and text_data.isdigit():
                        return {"status": "success", "code": text_data}

                    if action == "getCode" and self.server_type != "lion":
                        params["action"] = "getStatus"
                        resp2 = await client.get(self.url, params=params, timeout=15.0)
                        if resp2.status_code == 200:
                            t2 = resp2.text.strip()
                            if "STATUS_OK" in t2:
                                return {"status": "success", "code": t2.split(':')[1]}
                            if "STATUS_WAIT" in t2:
                                return {"status": "error", "message": "Code not arrived yet"}

                    return {"status": "error", "message": text_data}
                return {"status": "error", "message": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def calculate_price(self, provider_price):
        cost = float(provider_price)
        if self.profit_margin <= 0 and self.min_profit <= 0:
            return cost
        percent_profit = cost * (self.profit_margin / 100.0)
        final_profit = max(percent_profit, self.min_profit)
        final_price = cost + final_profit
        return math.ceil(final_price * 100) / 100.0


MESSAGES = {
    "en": {
        "banned_phone": "This phone number is banned from Telegram",
        "withdraw_approved": "<b>🎉 Congrats <code>{tx_id}</code> withdrawal {amount}$</b>",
        "withdraw_rejected": "<b>❌ Rejected <code>{tx_id}</code> withdrawal {amount}$</b>",
        "referral_earned": "🎁 You earned <b>${amount}</b> from a new referral!"
    },
    "ar": {
        "banned_phone": "هذا الرقم محظور من تليجرام",
        "withdraw_approved": "<b>🎉 تهانينا! تم قبول طلب السحب <code>{tx_id}</code> بمبلغ {amount}$</b>",
        "withdraw_rejected": "<b>❌ نعتذر، تم رفض طلب السحب <code>{tx_id}</code> بمبلغ {amount}$</b>",
        "referral_earned": "🎁 لقد ربحت <b>${amount}</b> من إحالة جديدة!"
    }
}

def get_text(key: str, lang: str = "ar", **kwargs) -> str:
    lang_msgs = MESSAGES.get(lang, MESSAGES["en"])
    text_val = lang_msgs.get(key, MESSAGES["en"].get(key, key))
    try:
        return text_val.format(**kwargs)
    except Exception:
        return text_val


# ==============================================================================
# 🔹 SECTION 4: KEYBOARDS (لوحات المفاتيح والأزرار)
# ==============================================================================

def main_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="Open", web_app=WebAppInfo(url=STORE_URL))
        ]
    ])

def admin_main_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📊 الإحصائيات (Stats)", callback_data="admin_stats")],
        [InlineKeyboardButton(text="👥 إدارة المستخدمين (Users)", callback_data="admin_users")],
        [InlineKeyboardButton(text="📦 إدارة المخزون (Stock)", callback_data="admin_stock")],
        [InlineKeyboardButton(text="📢 إذاعة رسالة (Broadcast)", callback_data="admin_broadcast")]
    ])

def admin_user_keyboard(user_id: int):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ إضافة رصيد", callback_data=f"usr_add_{user_id}"),
         InlineKeyboardButton(text="➖ خصم رصيد", callback_data=f"usr_sub_{user_id}")],
         [InlineKeyboardButton(text="الرجوع 🔙", callback_data="admin_main")]
    ])

def admin_back_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="الرجوع 🔙", callback_data="admin_main")]
    ])


# ==============================================================================
# 🔹 SECTION 5: MIDDLEWARES (الوسائط والتحقق في البوت)
# ==============================================================================

class MaintenanceMiddleware(BaseMiddleware):
    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any]
    ) -> Any:
        try:
            user_id = None
            if isinstance(event, Message):
                user_id = event.from_user.id
            elif isinstance(event, CallbackQuery):
                user_id = event.from_user.id
            elif isinstance(event, Update):
                if event.message:
                    user_id = event.message.from_user.id
                elif event.callback_query:
                    user_id = event.callback_query.from_user.id
                elif event.inline_query:
                    user_id = event.inline_query.from_user.id

            is_admin = user_id and user_id in STORE_ADMIN_IDS
            
            async with async_session() as session:
                stmt = select(AppSetting).where(AppSetting.key == "STORE_UNDER_MAINTENANCE")
                result = await session.execute(stmt)
                setting = result.scalar_one_or_none()
                is_maintenance = setting and str(setting.value).lower() == "true"
                
                ch_link = None
                if is_maintenance and not is_admin:
                    ch_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "UPDATES_CHANNEL"))).scalar_one_or_none()
                    ch_link = ch_obj.value if ch_obj else None

            if is_maintenance and not is_admin:
                target = None
                if isinstance(event, Message): target = event
                elif isinstance(event, CallbackQuery): target = event
                elif isinstance(event, Update):
                    if event.message: target = event.message
                    elif event.callback_query: target = event.callback_query

                if target:
                    markup = None
                    if ch_link:
                        markup = InlineKeyboardMarkup(inline_keyboard=[
                            [InlineKeyboardButton(text="Updates Channel 📢", url=ch_link)]
                        ])

                    if isinstance(target, Message):
                        await target.answer("<b>⚠️ The store is currently under maintenance.</b>", parse_mode="HTML", reply_markup=markup)
                    elif isinstance(target, CallbackQuery):
                        await target.answer("Maintenance Mode ⚠️", show_alert=True)
                    return

            return await handler(event, data)
        except Exception as e:
            logger.error(f"MaintenanceMiddleware Error: {e}")
            return await handler(event, data)


class SubscriptionMiddleware(BaseMiddleware):
    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any]
    ) -> Any:
        try:
            user_id = None
            target = None
            
            if isinstance(event, Message):
                user_id = event.from_user.id
                target = event
            elif isinstance(event, CallbackQuery):
                user_id = event.from_user.id
                target = event
            elif isinstance(event, Update):
                if event.message:
                    user_id = event.message.from_user.id
                    target = event.message
                elif event.callback_query:
                    user_id = event.callback_query.from_user.id
                    target = event.callback_query
            
            if not user_id or not target:
                return await handler(event, data)

            bot: Bot = data.get("bot")
            
            if user_id in STORE_ADMIN_IDS:
                return await handler(event, data)

            async with async_session() as session:
                result = await session.execute(select(SubscriptionChannel).where(SubscriptionChannel.bot_type == "store"))
                channels = result.scalars().all()

            if not channels:
                return await handler(event, data)

            not_subscribed = []
            for channel in channels:
                try:
                    chat_id = channel.username
                    member = await bot.get_chat_member(chat_id=chat_id, user_id=user_id)
                    if member.status in ["left", "kicked"]:
                        not_subscribed.append(channel)
                except Exception as e:
                    logger.error(f"Error checking sub for {chat_id}: {e}")
                    continue

            if not_subscribed:
                buttons = []
                for ch in not_subscribed:
                    link = ch.link if ch.link.startswith("http") else f"https://t.me/{ch.username.replace('@','')}"
                    buttons.append([InlineKeyboardButton(text=f"Join Channel", url=link)])
                
                kb = InlineKeyboardMarkup(inline_keyboard=buttons)
                
                msg = (
                    "🔒 <b>Subscription Required</b>\n\n"
                    "Sorry, you must join our channel first to use the bot:\n\n"
                    "✅ <b>After joining, send /start</b>"
                )
                
                if isinstance(target, Message):
                    await target.answer(msg, reply_markup=kb, parse_mode="HTML")
                elif isinstance(target, CallbackQuery):
                    await target.message.answer(msg, reply_markup=kb, parse_mode="HTML")
                    await target.answer()
                
                return

            return await handler(event, data)
        except Exception as e:
            logger.error(f"SubscriptionMiddleware Error: {e}")
            return await handler(event, data)


class UserUpdateMiddleware(BaseMiddleware):
    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any]
    ) -> Any:
        tg_user: TGUser = data.get("event_from_user")

        if tg_user and not tg_user.is_bot:
            try:
                async with async_session() as session:
                    user_id = tg_user.id
                    full_name = f"{tg_user.first_name or ''} {tg_user.last_name or ''}".strip() or None
                    username = tg_user.username or None

                    stmt = select(User).where(User.id == user_id)
                    result = await session.execute(stmt)
                    user = result.scalar_one_or_none()

                    referral_id = None
                    if not user or (not user.referred_by):
                        msg = None
                        if isinstance(event, Message):
                            msg = event
                        elif isinstance(event, Update) and event.message:
                            msg = event.message

                        if msg and msg.text and msg.text.startswith('/start') and len(msg.text.split()) > 1:
                            start_param = msg.text.split()[1]
                            if start_param.startswith("REF"):
                                try: referral_id = int(start_param.replace("REF", ""))
                                except: pass
                            else:
                                try: referral_id = int(start_param)
                                except: pass

                    is_new_join = False

                    if not user:
                        user = User(
                            id=user_id,
                            full_name=full_name,
                            username=username,
                            is_active_store=True,
                            referred_by=referral_id if (referral_id and referral_id != user_id) else None,
                            referral_bonus_awarded=False
                        )
                        session.add(user)
                        is_new_join = True
                        logger.info(f"Middleware: Created new user {user_id}")
                    else:
                        changed = False
                        if not user.referred_by and referral_id and referral_id != user_id:
                            user.referred_by = referral_id
                            changed = True

                        if not user.is_active_store:
                            user.is_active_store = True
                            changed = True
                            is_new_join = True

                        if user.full_name != full_name:
                            user.full_name = full_name
                            changed = True
                        if user.username != username:
                            user.username = username
                            changed = True

                    await session.commit()

                    if is_new_join:
                        bot = data.get("bot")
                        if bot:
                            await self._send_join_log(bot, tg_user)

            except Exception as e:
                logger.error(f"Error in UserUpdateMiddleware: {e}")

        return await handler(event, data)

    async def _send_join_log(self, bot, tg_user: TGUser):
        try:
            async with async_session() as session:
                obj = (await session.execute(
                    select(AppSetting).where(AppSetting.key == "store_join_log_channel_id")
                )).scalar_one_or_none()
                if not obj or not obj.value or not obj.value.strip():
                    return
                channel_id_raw = obj.value.strip()

                referrer_line = "—"
                user_record = (await session.execute(
                    select(User).where(User.id == tg_user.id)
                )).scalar_one_or_none()

                if user_record and user_record.referred_by:
                    referrer = (await session.execute(
                        select(User).where(User.id == user_record.referred_by)
                    )).scalar_one_or_none()
                    if referrer:
                        ref_name = referrer.full_name or str(referrer.id)
                        ref_user = f" — @{referrer.username}" if referrer.username else ""
                        referrer_line = f"{ref_name}{ref_user} — <code>{referrer.id}</code>"
                    else:
                        referrer_line = f"<code>{user_record.referred_by}</code>"

            if channel_id_raw.lstrip("-").isdigit():
                channel_id = int(channel_id_raw)
            else:
                channel_id = channel_id_raw

            full_name = f"{tg_user.first_name or ''} {tg_user.last_name or ''}".strip() or "—"
            username_line = f"@{tg_user.username}" if tg_user.username else "—"

            text = (
                f"🔔 <b>New Member Joined!</b>\n"
                f"┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄\n\n"
                f"👤  <b>{full_name}</b>\n\n"
                f"🏷️  <b>{username_line}</b>\n\n"
                f"🆔  <b>{tg_user.id}</b>\n\n"
                f"🤖  <b>STORE BOT</b>\n\n"
                f"🔗  <b>{referrer_line}</b>\n\n"
                f"┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄"
            )

            await bot.send_message(chat_id=channel_id, text=text, parse_mode="HTML")
        except Exception as e:
            logger.error(f"Middleware: Failed to send join log: {e}")


# ==============================================================================
# 🔹 SECTION 6: HANDLERS & BOT ROUTER (معالجات أوامر البوت)
# ==============================================================================

main_router = Router()

@main_router.message(Command("admin"))
async def cmd_admin(message: Message):
    user_id = message.from_user.id
    if user_id not in STORE_ADMIN_IDS:
        return
    
    admin_url = f"{WEBAPP_URL}/admin/store"
    markup = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Open", web_app=WebAppInfo(url=admin_url))]
    ])
    await message.answer(
        "👋 Welcome - Admin\n\n👇 Click the button below to continue",
        reply_markup=markup,
        parse_mode="HTML"
    )

@main_router.message(CommandStart())
async def cmd_start(message: Message, bot: Bot = None):
    if bot:
        try:
            await bot.delete_my_commands(scope=BotCommandScopeChat(chat_id=message.from_user.id))
            await bot.set_chat_menu_button(
                chat_id=message.from_user.id,
                menu_button=MenuButtonWebApp(text="Open", web_app=WebAppInfo(url=STORE_URL))
            )
        except Exception:
            pass

    user_id = message.from_user.id
    
    args = message.text.split()
    referral_id = None
    if len(args) > 1:
        start_param = args[1]
        if start_param.startswith("REF"):
            try: referral_id = int(start_param.replace("REF", ""))
            except ValueError: pass
        else:
            try: referral_id = int(start_param)
            except ValueError: pass
    
    async with async_session() as session:
        stmt = select(User).where(User.id == user_id)
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()
        
        if user and user.referred_by and not user.referral_bonus_awarded:
            referrer_id = user.referred_by
            async with async_session() as ref_session:
                referrer = (await ref_session.execute(select(User).where(User.id == referrer_id))).scalar_one_or_none()
                if referrer:
                    bonus_obj = (await ref_session.execute(select(AppSetting).where(AppSetting.key == "referral_join_bonus"))).scalar_one_or_none()
                    bonus_val = float(bonus_obj.value) if bonus_obj and bonus_obj.value else 0.005
                    
                    referrer.balance_store = (referrer.balance_store or 0.0) + bonus_val
                    referrer.referral_earnings = (referrer.referral_earnings or 0.0) + bonus_val
                    referrer.refer_count = (referrer.refer_count or 0) + 1
                    
                    user = await ref_session.merge(user)
                    user.referral_bonus_awarded = True
                    
                    txn = Transaction(user_id=referrer_id, type=TransactionType.REFERRAL, amount=bonus_val)
                    ref_session.add(txn)
                    
                    await ref_session.commit()
                    logger.info(f"Referral Awarded: User {user_id} joined via {referrer_id}, awarded ${bonus_val}")

                    try:
                        target_bot = bot or message.bot
                        ref_lang = referrer.language if referrer.language else "ar"
                        formatted_bonus = f"{bonus_val:.3f}" if f"{bonus_val:.3f}"[-1] != '0' else f"{bonus_val:.2f}"
                        msg_text = get_text("referral_earned", ref_lang, amount=formatted_bonus)
                        await target_bot.send_message(referrer_id, msg_text, parse_mode="HTML")
                    except Exception as send_err:
                        logger.error(f"Failed to send referral notification: {send_err}")
        
        if user and user.is_banned_store:
            support_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "SUPPORT_USERNAME"))).scalar_one_or_none()
            support_username = support_obj.value if support_obj else None
            
            markup = None
            if support_username:
                markup = InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="Contact Support 🎧", url=f"https://t.me/{support_username}")]
                ])
            
            await message.answer("<b>🚫 Your account has been suspended.</b>", parse_mode="HTML", reply_markup=markup)
            return
    
    await message.answer(
        "👋 Welcome\n\n👇 Click the button below to continue",
        reply_markup=main_keyboard(),
        parse_mode="HTML"
    )




# ==============================================================================
# 🔹 SECTION 7: BOT SERVICE & APPLICATION STARTUP (تشغيل النظام والسيرفر)
# ==============================================================================


async def start_bot_service(dp: Dispatcher, bot: Bot, name: str):
    """Safely starts the Store bot service."""
    try:
        me = await bot.get_me()
        logger.info(f"✅ SUCCESS: {name} Bot (@{me.username}) is connected and starting!")
        await dp.start_polling(bot)
    except Exception as e:
        logger.error(f"❌ FATAL ERROR in {name} Bot connection: {e}")

async def main():
    logger.info("Initializing Store Bot System...")
    
    # 1. Database Initialization
    try:
        await init_db()
        logger.info("Database initialized.")
    except Exception as e:
        logger.error(f"Database init failed: {e}")
        return

    # 2. Setup Store Bot
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN missing!")
        return
        
    bot_store = Bot(token=BOT_TOKEN)
    dp_store = Dispatcher()
    dp_store.include_router(main_router)
    
    # Middlewares
    dp_store.update.outer_middleware(MaintenanceMiddleware())
    dp_store.update.outer_middleware(UserUpdateMiddleware())
    dp_store.update.outer_middleware(SubscriptionMiddleware())

    # Attach bot to app state for Web Admin panel access
    app.state.bot_buyer = bot_store
    app.state.bot_store = bot_store
    
    # 3. Web Server Task
    port = int(os.environ.get("PORT", 8000))
    server_config = Config(app=app, host="0.0.0.0", port=port, log_level="info")
    server = Server(server_config)
    web_task = asyncio.create_task(server.serve())
    logger.info(f"Web Admin Panel task created on port {port}.")

    # 4. Clean side menu commands
    try:
        await bot_store.delete_my_commands()
        await bot_store.delete_my_commands(scope=BotCommandScopeAllPrivateChats())
        logger.info("Store Bot commands reset globally.")
    except Exception as e:
        logger.error(f"Failed to delete commands: {e}")

    # 5. Start Tasks
    tasks = [
        web_task,
        asyncio.create_task(start_bot_service(dp_store, bot_store, "Store"))
    ]

    await asyncio.gather(*tasks)


# ==============================================================================
# 🔹 SECTION 8: WEB ADMIN SERVER & FASTAPI ENDPOINTS (سيرفر لوحة التحكم واجهات الويب)
# ==============================================================================


app = FastAPI(title="Store Admin Panel")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

class AdminAuthRequest(BaseModel):
    user_id: int
    init_data: str

class StoreBuy(BaseModel):
    user_id: int
    country: str
    server_id: int | None = None
    init_data: str

class StockLoginStart(AdminAuthRequest):
    phone: str

class StockPhoneCheck(AdminAuthRequest):
    phone: str

class StockLoginComplete(AdminAuthRequest):
    phone: str
    code: str
    hash: str
    password: str = None
    country: str
    price: float

class BalanceUpdate(AdminAuthRequest):
    user_id_target: int
    amount: float
    type: str = "store"

class BanToggle(AdminAuthRequest):
    user_id_target: int
    bot_type: str
    banned: bool

class PriceUpdate(AdminAuthRequest):
    country_code: str
    country_name: str
    iso_code: str = "XX"
    price: float
    buy_price: float
    approve_delay: int

class UserStorePriceCreate(AdminAuthRequest):
    id: int | None = None
    user_id_target: int
    country_code: str
    iso_code: str = "XX"
    sell_price: float

class UserSync(AdminAuthRequest):
    user_id_target: int
    bot_type: str


async def check_and_alert_missing_price(country_name: str, phone_number: str, session):
    try:
        cp_stmt = select(CountryPrice).where(CountryPrice.country_name == country_name)
        cp_list = (await session.execute(cp_stmt)).scalars().all()
        sell_price = cp_list[0].price if cp_list else 0
        
        if sell_price <= 0:
            alert_msg = (
                f"⚠️ <b>Missing Price: {country_name}</b>\n"
                f"Stock added ({phone_number}) but price is $0.00.\n"
                f"Status: <b>HIDDEN</b> from store."
            )
            
            async def notify_admins():
                async with aiohttp.ClientSession() as http_session:
                    for admin_id in ADMIN_IDS:
                        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
                        payload = {"chat_id": admin_id, "text": alert_msg, "parse_mode": "HTML"}
                        try:
                            await http_session.post(url, json=payload, timeout=5)
                        except Exception: pass
            
            asyncio.create_task(notify_admins())
    except Exception as e:
        logger.error(f"Error checking missing price alert: {e}")

class DepositSubmit(BaseModel):
    user_id: int
    txid: str
    method: str = "Binance Pay"

def normalize_provider_countries(srv_countries):
    """Normalizes various API provider responses into a standard list of country dicts."""
    countries_list = []
    
    # 1. Super Parser: Find the node that actually contains country data
    def find_country_node(node):
        if isinstance(node, dict):
            # Case A: Dict with country keys (EG, PS, etc.)
            if any(k in node for k in ["EG", "PS", "SA", "US", "20", "966", "970"]):
                return node
            # Case B: Dict that contains common keys like price/count
            if any(k in node for k in ["price", "count", "rate", "cost", "stock"]):
                return node
            # Otherwise, drill down
            for k, v in node.items():
                res = find_country_node(v)
                if res: return res
        elif isinstance(node, list):
            # Case C: List of objects - check first few items
            for item in node[:3]:
                if isinstance(item, dict):
                    if any(k in item for k in ["price", "count", "rate", "cost", "stock"]):
                        return node # Return the whole list
                    res = find_country_node(item)
                    if res: return node # Return the whole list if children are good
        return None

    # Special handling for Spider Service typo-prone and split structure
    # result: { countries: {1: {ISO: price}}, cuantity: {1: {ISO: count}} }
    spider_prices = {}
    spider_counts = {}
    
    if isinstance(srv_countries, dict) and "result" in srv_countries:
        res = srv_countries["result"]
        if isinstance(res, dict):
            # Try to find prices
            p_node = res.get("countries")
            if isinstance(p_node, dict) and "1" in p_node: p_node = p_node["1"]
            if isinstance(p_node, dict): spider_prices = p_node
            
            # Try to find quantities (handling the 'cuantity' typo)
            q_node = res.get("cuantity") or res.get("quantity")
            if isinstance(q_node, dict) and "1" in q_node: q_node = q_node["1"]
            if isinstance(q_node, dict): spider_counts = q_node

    if spider_prices:
        # If we found Spider-specific split data, merge it
        for code, price in spider_prices.items():
            try:
                countries_list.append({
                    "country": code,
                    "price": float(price),
                    "count": int(spider_counts.get(code, 999))
                })
            except: continue
    else:
        # Fallback to Super Parser for TG-Lion and others
        data_node = find_country_node(srv_countries)
        if not data_node:
            data_node = srv_countries
            for key in ["result", "data", "countries_info", "countries"]:
                if isinstance(data_node, dict) and key in data_node:
                    data_node = data_node[key]
                    break
        
        if isinstance(data_node, dict):
            for code, val in data_node.items():
                if code.lower() in ["status", "message", "error", "ok", "msg", "currency", "success", "rate", "price", "count", "stock", "quantity", "qty", "server_time"]: continue
                if isinstance(val, dict):
                    entry = val.copy()
                    entry["country"] = code
                    countries_list.append(entry)
                elif isinstance(val, (int, float, str)):
                    try:
                        # Use a helper to clean price string if it's not a direct float
                        def clean_p(v):
                            if isinstance(v, (int, float)): return float(v)
                            try: return float(str(v).replace('$', '').replace('USD', '').strip().split()[0])
                            except: return 0.0

                        price_val = clean_p(val)
                        countries_list.append({
                            "country": code,
                            "count": 999,
                            "price": price_val
                        })
                    except: continue
        elif isinstance(data_node, list):
            # Normalize list items to have 'country' key
            for item in data_node:
                if not isinstance(item, dict): continue
                normalized = item.copy()
                if "country" not in normalized:
                    # Try to find country code in common keys
                    for k in ["id", "iso", "code", "name"]:
                        if k in normalized:
                            normalized["country"] = normalized[k]
                            break
                countries_list.append(normalized)
    
    return countries_list


class StoreSettingsSubmit(AdminAuthRequest):
    binance_api_key: str
    binance_api_secret: str
    binance_pay_id: str
    trx_address: str
    usdt_bep20_address: str

class GeneralSettingsSubmit(AdminAuthRequest):
    bot_name: str
    purchase_log_channel_id: str
    deposit_log_channel_id: str = ""

class ApiServerSubmit(AdminAuthRequest):
    id: int | None = None
    name: str
    url: str
    api_key: str
    server_type: str = "standard"
    extra_id: str | None = None
    profit_margin: float
    min_profit: float = 0.0
    is_active: bool

class MaintenanceToggle(AdminAuthRequest):
    enabled: bool

class ReferralSettingsSubmit(AdminAuthRequest):
    join_bonus: float
    commission_percent: float

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# SECURITY: OTP Cooldown Tracking
otp_cooldowns = {} # {phone_number: timestamp, user_id: timestamp}
OTP_COOLDOWN_SECONDS = 15

def generate_transaction_id():
    chars = string.ascii_uppercase + string.digits
    suffix = ''.join(random.choice(chars) for _ in range(10))
    return f"TC{suffix}"

def get_flag_emoji(country_code: str):
    """Convert ISO country code to flag emoji."""
    try:
        if not country_code or not isinstance(country_code, str) or len(country_code) != 2:
            return "🌐"
        return "".join(chr(ord(c) + 127397) for c in country_code.upper())
    except:
        return "🌐"

_bot_info_cache = {}

def verify_telegram_auth(init_data: str, bot_token: str, expected_user_id: int) -> bool:
    """Verifies that the request actually comes from the claimed user using Telegram Web App Hash."""
    try:
        if not init_data: return False
        parsed_data = dict(parse_qsl(init_data))
        hash_str = parsed_data.pop('hash', None)
        if not hash_str: return False
        
        # Check if the user ID in init_data matches the claimed user_id
        user_obj = json.loads(parsed_data.get('user', '{}'))
        if int(user_obj.get('id', 0)) != expected_user_id:
            logger.warning(f"Auth Mismatch: Claims {expected_user_id} but InitData is for {user_obj.get('id')}")
            return False
            
        data_check_string = '\n'.join([f"{k}={v}" for k, v in sorted(parsed_data.items())])
        secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
        calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        return calculated_hash == hash_str
    except Exception as e:
        logger.error(f"Auth Verification Exception: {e}")
        return False

def verify_admin_auth_multi(init_data: str, user_id: int, bot_type: str = "store") -> bool:
    """Helper to verify admin auth against store admin IDs."""
    if not init_data or not user_id: return False
    if user_id not in STORE_ADMIN_IDS: return False
    return verify_telegram_auth(init_data, BOT_TOKEN, user_id)


def verify_user_auth_multi(init_data: str, user_id: int) -> bool:
    """Helper to verify user auth against bot token."""
    if not init_data or not user_id: return False
    return verify_telegram_auth(init_data, BOT_TOKEN, user_id)


async def send_purchase_log(user_id: int, country_name: str, price: float, phone: str, code: str, password: str = None):
    """Send a purchase log to the configured Telegram channel."""
    try:
        import requests
        
        async with async_session() as session:
            stmt = select(AppSetting).where(AppSetting.key == "purchase_log_channel_id")
            res = await session.execute(stmt)
            obj = res.scalar_one_or_none()
            if not obj or not obj.value:
                logger.info("Purchase log skipped: No channel ID configured.")
                return
            channel_id = obj.value.strip()
            logger.info(f"Resolved Purchase Log Channel ID: {channel_id}")
            # Standardize channel ID
            if channel_id.isdigit() or (channel_id.startswith('-') and channel_id[1:].isdigit()):
                if not channel_id.startswith('-100') and not channel_id.startswith('-'):
                    channel_id = f"-100{channel_id}"
            logger.info(f"Resolved Purchase Log Channel ID: {channel_id}")
            
        flag = "🌐"
        try:
            # Pass the phone to resolve_country_info to get accurate flag/name
            _, _, iso = resolve_country_info(country_name, full_phone=phone)
            if iso and iso != "XX": 
                flag = get_flag_emoji(iso)
        except: pass
        
        masked_id = str(user_id)
        if len(masked_id) > 6:
            masked_id = f"••{masked_id[2:4]}•••••"
        else:
            masked_id = f"••{masked_id[:2]}•••"
            
        masked_phone = str(phone)
        if len(masked_phone) > 7:
            # Mask like +96655890••••
            # We take the first 9 chars (usually including + and country code and some digits)
            masked_phone = f"{masked_phone[:9]}••••"
            
        # HTML escaping
        safe_country = country_name.replace('<', '&lt;').replace('>', '&gt;')
        # Simplify: "Iran, Islamic Republic of" → "Iran"
        display_country = clean_display_name(safe_country)
        display_password = password if password else "None"
        
        # Proper price formatting: 3 decimals if needed, else 2
        price_str = f"{price:.3f}" if f"{price:.3f}"[-1] != '0' else f"{price:.2f}"
        
        message = (
            "<b>• account purchased successfully .</b>\n\n"
            f"<b>• For country :- {display_country}{flag} </b>\n"
            "<b>• Application Type :- Telegram .</b>\n\n"
            f"<b>• Number :- {masked_phone} 📞.</b>\n"
            f"<b>• Activation code :- {code} 💬.</b>\n\n"
            f"<b>• Password :- {display_password} 🔑.</b>\n"
            f"<b>• Price :- ${price_str} 💵.</b>\n\n"
            f"<b>• ID buyer :- {masked_id} 👨🏻‍💻 .</b>"
        )
        
        payload = {
            "chat_id": channel_id,
            "text": message,
            "parse_mode": "HTML"
        }
        
        if not _bot_info_cache.get("username"):
            try:
                r = requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/getMe", timeout=5)
                if r.ok:
                    data = r.json()
                    _bot_info_cache["username"] = data["result"].get("username", "")
            except: pass
            
        bot_username = _bot_info_cache.get("username", "")
        if bot_username:
            payload["reply_markup"] = {
                "inline_keyboard": [[{"text": "• Buy number from bot 🖥 .", "url": f"https://t.me/{bot_username}"}]]
            }
        
        def do_send():
            try:
                r = requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json=payload, timeout=10)
                if not r.ok:
                    logger.error(f"Telegram API Error: {r.text} | Payload: {payload}")
            except Exception as e:
                logger.error(f"Requests Error in do_send: {e}")
            
        await asyncio.to_thread(do_send)
    except Exception as e:
        logger.error(f"Error in send_purchase_log: {e}")

async def send_sourcing_price_log(country_name: str, iso_code: str, country_code: str, buy_price: float, approve_delay: int, quantity: int = 1000):
    """Send a price update log to the configured Telegram channel."""
    import html as _html
    try:
        async with async_session() as session:
            stmt = select(AppSetting).where(AppSetting.key == "sourcing_log_channel_id")
            res = await session.execute(stmt)
            obj = res.scalar_one_or_none()
            if not obj or not obj.value:
                logger.warning("send_sourcing_price_log: sourcing_log_channel_id is not configured.")
                return
            channel_id = obj.value.strip()

            # Standardize channel ID
            if channel_id.isdigit() or (channel_id.startswith('-') and not channel_id.startswith('-100')):
                if not channel_id.startswith('-'):
                    channel_id = f"-100{channel_id}"
                elif channel_id.startswith('-') and not channel_id.startswith('-100'):
                    channel_id = f"-100{channel_id[1:]}"


        flag = get_flag_emoji(iso_code)
        c_name = str(country_name or "Unknown")
        for e in ["\U0001f1f8\U0001f1e6", "\U0001f1ea\U0001f1ec", "\U0001f1fa\U0001f1fe", "\U0001f310"]:
            c_name = c_name.replace(e, "")
        clean_name = _html.escape(c_name.strip())

        buy_str = f"{buy_price:.3f}".rstrip('0').rstrip('.')
        if '.' not in buy_str:
            buy_str = f"{buy_price:.2f}"

        message = (
            f"- {clean_name} - {flag} - ${buy_str}\n\n"
            f"- Quantity - {quantity} - +{_html.escape(str(country_code))} - {_html.escape(str(iso_code))}\n\n"
            f"- Confirmation time [ {approve_delay} ] second\n\n"
            "-The bot is always open. I will announce on this channel if the price goes up or down"
        )

        def _send_tg():
            _username = ""
            try:
                r0 = urllib.request.Request(f"https://api.telegram.org/bot{SELLER_BOT_TOKEN}/getMe")
                with urllib.request.urlopen(r0, timeout=5) as rr:
                    d0 = json.loads(rr.read().decode())
                    if d0.get("ok"):
                        _username = d0["result"].get("username", "")
            except Exception:
                pass

            payload = {"chat_id": channel_id, "text": message, "parse_mode": "HTML"}
            if _username:
                payload["reply_markup"] = {
                    "inline_keyboard": [[{"text": "\U0001f916 BOT \U0001f916", "url": f"https://t.me/{_username}"}]]
                }

            req = urllib.request.Request(
                f"https://api.telegram.org/bot{SELLER_BOT_TOKEN}/sendMessage",
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())

        result = await asyncio.to_thread(_send_tg)
        if not result.get("ok"):
            logger.error(f"Telegram API rejected sourcing log: {result}")
        else:
            logger.info(f"Sourcing price log sent -> channel={channel_id} country={country_name}")

    except Exception as e:
        logger.error(f"Error sending sourcing price log: {e}")

# ---- end send_sourcing_price_log ----


def resolve_country_info(country_code_str: str, full_phone: str = None):
    """Resolve ISO code and Country Name. Handles numeric codes, Alpha-2, and Alpha-3."""
    try:
        code_str = str(country_code_str).strip().upper().lstrip('+')
        if not code_str: return "Unknown", "🌐", "XX"

        # 1. Handle if it's already an ISO code (Alpha-2 or Alpha-3)
        if not code_str.isdigit() and len(code_str) in [2, 3]:
            try:
                country = None
                if len(code_str) == 2:
                    country = pycountry.countries.get(alpha_2=code_str)
                else:
                    country = pycountry.countries.get(alpha_3=code_str)
                
                if country:
                    name = re.sub(r'\s*\(?[A-Z]{2,3}\)?\s*$', '', country.name).strip()
                    iso = country.alpha_2
                    return name, get_flag_emoji(iso), iso
            except: pass

        # 2. Handle if full_phone is provided
        if full_phone:
            try:
                parsed = phonenumbers.parse(full_phone if full_phone.startswith('+') else f"+{full_phone}")
                iso_code = phonenumbers.region_code_for_number(parsed)
                country = pycountry.countries.get(alpha_2=iso_code)
                name = country.name if country else iso_code
                name = re.sub(r'\s*\(?[A-Z]{2,3}\)?\s*$', '', name).strip()
                return name, get_flag_emoji(iso_code), iso_code
            except: pass

        # 3. Handle numeric calling code prefix
        if code_str.isdigit():
            try:
                numeric_code = int(code_str)
                iso_code = phonenumbers.region_code_for_country_code(numeric_code)
                flag = get_flag_emoji(iso_code)
                
                name = f"Country {numeric_code}"
                country = pycountry.countries.get(alpha_2=iso_code)
                if country:
                    name = re.sub(r'\s*\(?[A-Z]{2,3}\)?\s*$', '', country.name).strip()
                return name, flag, iso_code
            except: pass
        
        return f"Code {code_str}", "🌐", "XX"
    except Exception as e:
        logger.error(f"Error resolving country {country_code_str}: {e}")
        return f"Code {country_code_str}", "🌐", "XX"

def clean_display_name(raw_name: str) -> str:
    """Removes trailing ISO codes like EG, (EG), or [EG], and resolves standalone codes."""
    if not raw_name: return raw_name
    
    # Standalone code resolution map
    codes_map = {
        "EG": "Egypt",
        "US": "United States",
        "UK": "United Kingdom",
        "SA": "Saudi Arabia",
        "RU": "Russia",
        "UA": "Ukraine"
    }
    
    # If the name itself is just a code, resolve it
    trimmed = raw_name.strip().upper()
    if trimmed in codes_map:
        return codes_map[trimmed]
    
    # Split by comma and parenthesis to take the first part
    raw_name = raw_name.split(',')[0].split('(')[0]
    
    removals = [
        "Islamic Republic of",
        "Province of China",
        "Republic of",
        "Federation",
        "United Republic of",
        "Plurinational State of",
        "Bolivarian Republic of",
        "People's Democratic Republic",
        "Arab Republic",
        "Democratic "
    ]
    for r in removals:
        raw_name = raw_name.replace(r, "")
        
    # Handle formats like "Egypt EG", "Egypt (EG)", "Egypt [EG]"
    clean = re.sub(r'\s*[\(\[]?[A-Z]{2,3}[\)\]]?\s*$', '', raw_name)
    return clean.strip()

# ─── Babel Locale Map ───
_LANG_TO_BABEL = {
    "en": "en",
    "ar": "ar",
    "zh": "zh_Hans",
    "bn": "bn",
    "fa": "fa",
    "ru": "ru",
    "uz": "uz",
    "es": "es",
    "tr": "tr",
}

def get_localized_country_name(iso_code: str, lang: str) -> str:
    """Return country name localized to the given language using Babel."""
    if not iso_code or iso_code == 'XX':
        return "ERROR_ISO_XX"
    try:
        from babel import Locale
        from babel.core import UnknownLocaleError
        locale_str = _LANG_TO_BABEL.get(lang, "en")
        try:
            locale = Locale.parse(locale_str)
        except UnknownLocaleError:
            locale = Locale.parse("en")
        name = locale.territories.get(iso_code.upper())
        return name if name else f"ERROR_NO_NAME_FOR_{iso_code}"
    except Exception as e:
        return f"ERROR_BABEL_{str(e)}"

app = FastAPI(title="Store Admin Panel")

@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    # Apply no-cache to both API and HTML pages to prevent aggressive caching in Telegram
    if request.url.path.startswith("/api/") or request.url.path.startswith("/seller") or request.url.path.startswith("/admin"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.get("/admin/store", response_class=HTMLResponse)
async def admin_store(request: Request):
    try:
        return templates.TemplateResponse(request=request, name="admin_store.html", context={"ADMIN_IDS": STORE_ADMIN_IDS})
    except Exception as e:
        logger.error(f"Error rendering store dashboard: {e}")
    return templates.TemplateResponse(request=request, name="admin_store.html", context={"ADMIN_IDS": []})

@app.get("/", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/store", response_class=HTMLResponse)
async def store_page(request: Request):
    return templates.TemplateResponse(request=request, name="store.html")

@app.get("/api/store/data")
async def get_store_data(user_id: int = None, init_data: str = None):
    try:
        if user_id and init_data:
            if not verify_telegram_auth(init_data, BOT_TOKEN, user_id):
                raise HTTPException(status_code=401, detail="Unauthorized identity")
        
        async with async_session() as session:
            # CHECK MAINTENANCE MODE FIRST (Admins bypass)
            mnt_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "STORE_UNDER_MAINTENANCE"))).scalar_one_or_none()
            maintenance_mode = (mnt_obj.value.lower() == "true") if mnt_obj else False
            
            # Support & Channel settings
            support_username = (await session.execute(select(AppSetting).where(AppSetting.key == "SUPPORT_USERNAME"))).scalar_one_or_none()
            updates_channel = (await session.execute(select(AppSetting).where(AppSetting.key == "UPDATES_CHANNEL"))).scalar_one_or_none()

            if maintenance_mode and user_id not in ADMIN_IDS:
                return {
                    "maintenance_store": True,
                    "support_username": support_username.value if support_username else "",
                    "updates_channel": updates_channel.value if updates_channel else ""
                }

            if user_id:
                user = await session.get(User, user_id)
                if user and user.is_banned_store and user_id not in ADMIN_IDS:
                    return {
                        "is_banned": True,
                        "support_username": support_username.value if support_username else "",
                        "updates_channel": updates_channel.value if updates_channel else ""
                    }

            # 0. Global Settings
            local_enabled_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "local_server_enabled"))).scalar_one_or_none()
            local_enabled = (local_enabled_obj.value.lower() == "true") if local_enabled_obj else True

            # 1. Local Stock
            countries_map = {}
            local_results = []
            if local_enabled:
                stmt = select(Account.country, func.count(Account.id).label('cnt')).where(
                    Account.status == AccountStatus.AVAILABLE,
                    Account.server_id == None
                ).group_by(Account.country)
                
                local_results = (await session.execute(stmt)).all()
                logger.info(f"Local results: {len(local_results)} countries")
                
                for row in local_results:
                    raw_country, count = row
                    # Resolve real name and flag for local countries
                    res_name, res_flag, res_iso = resolve_country_info(raw_country)
                    # Use resolved name if it's not "Code X", otherwise keep raw_country
                    display_name = res_name if "Code " not in res_name else raw_country
                    
                    map_key = f"{display_name}|__local__"
                    countries_map[map_key] = {
                        "name": display_name, 
                        "flag": res_flag,
                        "iso": res_iso,
                        "count": count, 
                        "server_id": None, 
                        "server_name": "Server 1"
                    }

            server_names = []
            if local_enabled and len(local_results) > 0:
                server_names.append("Server 1")
                
            # 2. External Stock
            active_servers = (await session.execute(select(ApiServer).where(ApiServer.is_active == True))).scalars().all()
            for srv in active_servers:
                server_names.append(srv.name)
                
            logger.info(f"Active external servers: {len(active_servers)}")
            for srv in active_servers:
                try:
                    logger.info(f"Processing server: {srv.name} ({srv.url})")
                    provider = ExternalProvider(
                        srv.name, srv.url, srv.api_key, srv.profit_margin,
                        min_profit=getattr(srv, 'min_profit', 0.0),
                        server_type=getattr(srv, 'server_type', 'standard'),
                        extra_id=getattr(srv, 'extra_id', None)
                    )
                    srv_countries = await provider.get_countries()
                    
                    if not srv_countries:
                        logger.warning(f"Server {srv.name} returned no data.")
                        continue

                    # Handle common error formats in responses
                    if isinstance(srv_countries, dict) and srv_countries.get("status") in ["error", "fail"]:
                        logger.error(f"Server {srv.name} API Error: {srv_countries.get('message')}")
                        continue

                    # Normalize srv_countries to a list of dicts
                    countries_list = normalize_provider_countries(srv_countries)
                    
                    for c in countries_list:
                        raw_name = c.get("name") or c.get("country") or c.get("country_name") or c.get("country_code")
                        if not raw_name: continue
                        
                        # Use 'code' field (ISO Alpha-2) if available for accurate resolution
                        iso_from_data = c.get("code") or c.get("iso") or c.get("country_code")
                        if iso_from_data and len(str(iso_from_data).strip()) == 2:
                            resolved_name, resolved_flag, resolved_iso = resolve_country_info(str(iso_from_data).strip())
                        else:
                            resolved_name, resolved_flag, resolved_iso = resolve_country_info(str(raw_name))
                        
                        # Use resolved name if good, otherwise use raw name but clean emoji flags
                        if resolved_name and "Code " not in resolved_name:
                            name = resolved_name
                        else:
                            # Clean emoji flags from raw name to avoid duplication
                            import re as _re
                            name = _re.sub(r'[\U0001F1E0-\U0001F1FF]{2}', '', str(raw_name)).strip()
                            if not name: name = str(raw_name)
                        
                        try:
                            # Support all common quantity field names: count, qty, stock, quantity
                            # Default to 999 if missing or 0, to match dictionary parser behavior for "unlimited" or unknown stock
                            raw_count = c.get("count", c.get("qty", c.get("stock", c.get("quantity"))))
                            if raw_count is None:
                                count = 999
                            else:
                                try: count = int(raw_count)
                                except: count = 999
                            
                            # Support multiple price keys: price, rate, cost, amount, value
                            raw_p = c.get("price", c.get("rate", c.get("cost", c.get("amount", c.get("value", 0)))))
                            def clean_p(v):
                                if isinstance(v, (int, float)): return float(v)
                                try: return float(str(v).replace('$', '').replace('USD', '').strip().split()[0])
                                except: return 0.0
                            
                            p_price = clean_p(raw_p)
                            if count <= 0: continue
                            
                            map_key = f"{name}|{srv.name}"
                            if map_key not in countries_map:
                                countries_map[map_key] = {
                                    "name": name,
                                    "flag": resolved_flag,
                                    "iso": resolved_iso,
                                    "count": count,
                                    "server_id": srv.id,
                                    "server_name": srv.name,
                                    "p_price": p_price,
                                    "calc_price": provider.calculate_price(p_price)
                                }
                            else:
                                countries_map[map_key]["count"] += count
                        except Exception as parse_err:
                            logger.warning(f"[{srv.name}] Failed to parse entry: {c} — {parse_err}")
                            continue

                except Exception as srv_err:
                    logger.error(f"Error processing server {srv.name}: {srv_err}")
                    continue

            # 3. Final Assembly with Metadata & Pricing
            countries = []
            
            # Pre-fetch all pricing data to avoid N+1 queries
            # Pre-fetch all pricing data
            all_cp = (await session.execute(select(CountryPrice))).scalars().all()
            # Map by name, ISO, and country code for better matching
            cp_name_map = {cp.country_name: cp for cp in all_cp}
            cp_iso_map = {cp.iso_code: cp for cp in all_cp if cp.iso_code and cp.iso_code != 'XX'}
            cp_code_map = {cp.country_code.strip().replace('+', ''): cp for cp in all_cp}
            
            all_usp = []
            if user_id:
                all_usp = (await session.execute(select(UserStorePrice).where(UserStorePrice.user_id == user_id))).scalars().all()
            usp_map = {usp.country_code: usp for usp in all_usp}

            for map_key, c_data in countries_map.items():
                name = c_data["name"]
                flag = c_data.get("flag", "🌐")
                is_local = (c_data.get("server_id") is None)
                
                # 1. Determine Base Price
                if is_local:
                    # Default local price if not in DB
                    price = 1.0
                else:
                    # External: API Cost + Profit Margin
                    price = c_data.get("calc_price", 1.0)
                
                # 2. Apply CountryPrice Overrides
                # Try match by ISO first (most accurate), then by name, then by calling code
                cp = cp_iso_map.get(c_data.get("iso")) or cp_name_map.get(name) or cp_code_map.get(str(name).strip().replace('+', ''))
                
                if cp:
                    # Always use flag from DB if available (for both local and external)
                    flag = get_flag_emoji(cp.iso_code)
                    
                    # Price Override Logic:
                    if is_local:
                        # Local stock: ALWAYS use the price from the Selling Prices table
                        price = cp.price
                    # External stock: We IGNORE the Selling Prices table for price overrides,
                    # as per user request ("this page should control local inventory only").
                    # It will use the 'price' calculated above (API Cost + Profit Margin).
                
                # 3. User-Specific Price Override (highest priority)
                is_sp = False
                if is_local and cp:
                    is_sp = True

                if user_id and is_local:
                    # Match logic for UserStorePrice:
                    # 1. By ISO code (most accurate)
                    # 2. By Name
                    # 3. By Country Code (if available)
                    
                    usp = None
                    iso_key = c_data.get("iso")
                    if iso_key and iso_key != 'XX':
                        # Try to find a USP that has this ISO
                        usp = next((u for u in all_usp if u.iso_code == iso_key), None)
                    
                    if not usp:
                        # Try matching by name
                        usp = next((u for u in all_usp if u.country_code == name), None)
                    
                    if not usp and is_local:
                        # For local items, we might have the code from the CP entry
                        if cp:
                            cc_clean = cp.country_code.strip().replace('+', '')
                            usp = next((u for u in all_usp if u.country_code == cc_clean or u.country_code == f"+{cc_clean}"), None)

                    if usp:
                        price = usp.sell_price
                        is_sp = True

                if price > 0:
                    countries.append({
                        "name": name,
                        "flag": flag,
                        "iso": c_data.get("iso", "XX"),
                        "buy_price": price,
                        "count": c_data["count"],
                        "server_id": c_data.get("server_id"),
                        "server_name": c_data.get("server_name", "Server 1"),
                        "is_selling_price": is_sp
                    })
            
            # Sort by count (descending) and then name (ascending)
            countries.sort(key=lambda x: (-x["count"], x["name"]))
            
            # User balance & Stats
            balance = 0.0
            total_orders = 0
            total_spent = 0.0
            total_deposits = 0
            completed_orders = 0
            active_orders = 0
            unique_countries = 0
            referral_count = 0
            referral_earnings = 0.0
            if user_id:
                user = await session.get(User, user_id)
                if user:
                    balance = user.balance_store
                    total_orders = (await session.execute(select(func.count(Account.id)).where(Account.buyer_id == user_id))).scalar() or 0
                    
                    spent_val = (await session.execute(
                        select(func.sum(Transaction.amount)).where(
                            Transaction.user_id == user_id,
                            Transaction.type == TransactionType.BUY
                        )
                    )).scalar() or 0.0
                    total_spent = abs(float(spent_val))

                    # Personalized stats
                    total_deposits = (await session.execute(select(func.count(Deposit.id)).where(Deposit.user_id == user_id))).scalar() or 0
                    completed_orders = (await session.execute(
                        select(func.count(Account.id)).where(Account.buyer_id == user_id, Account.otp_code != None)
                    )).scalar() or 0
                    active_orders = (await session.execute(
                        select(func.count(Account.id)).where(Account.buyer_id == user_id, Account.otp_code == None)
                    )).scalar() or 0
                    unique_countries = (await session.execute(
                        select(func.count(func.distinct(Account.country))).where(Account.buyer_id == user_id)
                    )).scalar() or 0
                    
                    referral_count = (await session.execute(
                        select(func.count(User.id)).where(User.referred_by == user_id)
                    )).scalar() or 0
                    referral_earnings = user.referral_earnings or 0.0

            # Calculate Stats
            total_numbers = sum(c['count'] for c in countries)
            countries_count = len(set(c['name'] for c in countries))
            lowest_price = min((c['buy_price'] for c in countries), default=0.0)

            # Fetch bot name and username
            bot_name = "Numbers Store"
            bot_username = "BotUsername"
            try:
                def fetch_name():
                    try:
                        req = urllib.request.Request(f"https://api.telegram.org/bot{BOT_TOKEN}/getMe")
                        with urllib.request.urlopen(req, timeout=2) as r:
                            res_data = json.loads(r.read().decode())
                            if res_data.get("ok"):
                                return res_data["result"].get("first_name", "Numbers Store"), res_data["result"].get("username", "BotUsername")
                    except: return "Numbers Store", "BotUsername"
                bot_name, bot_username = await asyncio.to_thread(fetch_name)
            except: pass

            # Fetch Deposit Addresses
            addr_keys = ["BINANCE_PAY_ID", "TRX_ADDRESS", "USDT_BEP20_ADDRESS"]
            addr_settings = {}
            for k in addr_keys:
                obj = (await session.execute(select(AppSetting).where(AppSetting.key == k))).scalar_one_or_none()
                addr_settings[k] = obj.value if obj and obj.value else ""

            final_binance_pay = addr_settings.get("BINANCE_PAY_ID") or DEPOSIT_ADDRESS
            final_trx = addr_settings.get("TRX_ADDRESS") or ""
            final_usdt_bep20 = addr_settings.get("USDT_BEP20_ADDRESS") or ""

            # Fetch Referral Settings
            ref_bonus_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "referral_join_bonus"))).scalar_one_or_none()
            ref_comm_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "referral_commission_percent"))).scalar_one_or_none()
            
            ref_bonus = float(ref_bonus_obj.value) if ref_bonus_obj and ref_bonus_obj.value else 0.005
            ref_comm = float(ref_comm_obj.value) if ref_comm_obj and ref_comm_obj.value else 1.0

        return {
            "maintenance_mode": False,
            "bot_name": bot_name,
            "bot_username": bot_username,
            "countries": countries,
            "servers": server_names,
            "referral_join_bonus": ref_bonus,
            "referral_commission_percent": ref_comm,
            "user": {
                "balance": balance,
                "total_orders": total_orders,
                "total_spent": total_spent,
                "total_deposits": total_deposits,
                "completed_orders": completed_orders,
                "active_orders": active_orders,
                "unique_countries": unique_countries,
                "referral_count": referral_count,
                "referral_earnings": referral_earnings
            },
            "stats": {
                "total_numbers": total_numbers,
                "countries_count": countries_count,
                "lowest_price": lowest_price
            },
            "deposit_methods": {
                "binance_pay": final_binance_pay,
                "trx_trc20": final_trx,
                "usdt_bep20": final_usdt_bep20
            },
            "support_username": support_username.value if support_username else "",
            "updates_channel": updates_channel.value if updates_channel else ""
        }
    except Exception as e:
        logger.error(f"Store Data Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/store/buy")
async def store_buy(data: StoreBuy):
    logger.info(f"Store Buy Request: user_id={data.user_id}, country={data.country}, server_id={data.server_id}")
    try:
        async with async_session() as session:
            # 1. AUTH VERIFICATION
            if not verify_telegram_auth(data.init_data, BOT_TOKEN, data.user_id):
                raise HTTPException(status_code=401, detail="Unauthorized: Telegram identity verification failed.")

            # Secure User Fetch with Row Locking
            user = await session.get(User, data.user_id, with_for_update=True)
            if not user: raise HTTPException(status_code=404, detail="User not found")
            
            # 0. Local Server Toggle
            local_enabled_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "local_server_enabled"))).scalar_one_or_none()
            local_enabled = (local_enabled_obj.value.lower() == "true") if local_enabled_obj else True

            # 1. Local Stock Check
            account = None
            if local_enabled and not data.server_id:
                stmt = select(Account).where(
                    Account.country == data.country, 
                    Account.status == AccountStatus.AVAILABLE,
                    Account.server_id == None
                ).limit(1)
                account = (await session.execute(stmt)).scalar_one_or_none()
            
            # 1. Price determination
            cp = (await session.execute(select(CountryPrice).where(CountryPrice.country_name == data.country))).scalar()
            
            # Initial default
            final_price = 1.0

            target_srv = None
            external_country_code = None
            is_local = False
            
            if account:
                is_local = True
                final_price = cp.price if cp else 1.0
            else:
                # 2. Try External Servers
                # If server_id is provided, only look at that server. Otherwise, check all active.
                if data.server_id:
                    active_servers = (await session.execute(select(ApiServer).where(ApiServer.id == data.server_id, ApiServer.is_active == True))).scalars().all()
                else:
                    active_servers = (await session.execute(select(ApiServer).where(ApiServer.is_active == True))).scalars().all()
                
                last_error = "Out of stock"
                
                for srv in active_servers:
                    provider = ExternalProvider(
                        srv.name, srv.url, srv.api_key, srv.profit_margin,
                        min_profit=getattr(srv, 'min_profit', 0.0),
                        server_type=getattr(srv, 'server_type', 'standard'),
                        extra_id=getattr(srv, 'extra_id', None)
                    )
                    srv_countries = await provider.get_countries()
                    if not srv_countries: continue
                    
                    # Use helper for normalization
                    countries_list = normalize_provider_countries(srv_countries)

                    def get_c(item):
                        rc = item.get("count", item.get("qty", item.get("stock", item.get("quantity"))))
                        try: return int(rc) if rc is not None else 999
                        except: return 999

                    server_matched = False
                    for c in countries_list:
                        if get_c(c) <= 0: continue
                        
                        raw_c = c.get("name") or c.get("country") or c.get("country_name") or c.get("country_code")
                        iso_hint = c.get("code") or c.get("iso") or c.get("country_code")
                        
                        # Resolve name for comparison
                        res_name, _, _ = resolve_country_info(str(iso_hint if (iso_hint and len(str(iso_hint))==2) else raw_c))
                        
                        if res_name == data.country or raw_c == data.country:
                            # Match found! Attempt to buy from THIS server
                            external_country_code = c.get("country")
                            cost_price = float(c.get("price", 0))
                            final_price = provider.calculate_price(cost_price)
                            
                            # Check user balance before attempting
                            if user.balance_store < final_price:
                                raise HTTPException(status_code=400, detail="Insufficient balance")

                            buy_res = await provider.buy_number(external_country_code)
                            if buy_res.get("status") == "success":
                                # SUCCESS! Record and return
                                user.balance_store -= final_price
                                new_acc = Account(
                                    phone_number=buy_res.get("number"),
                                    country=data.country,
                                    status=AccountStatus.SOLD,
                                    price=final_price,
                                    locked_buy_price=cost_price,
                                    buyer_id=user.id,
                                    purchased_at=datetime.utcnow(),
                                    server_id=srv.id,
                                    hash_code=buy_res.get("hash_code")
                                )
                                session.add(new_acc)
                                txn = Transaction(user_id=user.id, type=TransactionType.BUY, amount=-final_price)
                                session.add(txn)
                                await session.commit()
                                return {"status": "success", "phone": new_acc.phone_number, "id": new_acc.id}
                            else:
                                last_error = str(buy_res.get("message", "API provider error"))
                                logger.warning(f"Purchase failed on {srv.name}: {last_error}. Trying next server...")
                                server_matched = True # We matched the country but purchase failed
                                break # Try next server
                    # End of country loop
                
                # If we reach here, all active servers failed to provide the number
                msg_lower = last_error.lower()
                if any(word in msg_lower for word in ["balance", "رصيد", "money", "fund", "credit", "insufficient"]):
                    raise HTTPException(status_code=400, detail="Out of stock")
                else:
                    raise HTTPException(status_code=400, detail=last_error)

            # 3. Handle Local Purchase Execution
            if is_local and account:
                # Resolve Personalized Pricing
                _, _, res_iso = resolve_country_info(data.country)
                
                async with async_session() as inner_session:
                    stmt = select(UserStorePrice).where(UserStorePrice.user_id == data.user_id)
                    user_prices = (await inner_session.execute(stmt)).scalars().all()
                    usp = None
                    if res_iso and res_iso != 'XX':
                        usp = next((u for u in user_prices if u.iso_code == res_iso), None)
                    if not usp:
                        usp = next((u for u in user_prices if u.country_code == data.country), None)
                    if not usp and cp:
                        cc_clean = cp.country_code.strip().replace('+', '')
                        usp = next((u for u in user_prices if u.country_code == cc_clean or u.country_code == f"+{cc_clean}"), None)
                    if usp:
                        final_price = usp.sell_price
                
                if final_price <= 0:
                    raise HTTPException(status_code=400, detail="This country is currently unavailable (Price not set)")
                
                if user.balance_store < final_price:
                    raise HTTPException(status_code=400, detail="Insufficient balance")

                # Execute Local Purchase
                user.balance_store -= final_price
                account.status = AccountStatus.SOLD
                account.buyer_id = user.id
                account.otp_code = None
                account.purchased_at = datetime.utcnow()
                account.price = final_price
                txn = Transaction(user_id=user.id, type=TransactionType.BUY, amount=-final_price)
                session.add(txn)
                await session.commit()
                
                # Background cleaning: Reset authorizations and remove 2FA
                # clean_account_for_buyer is defined inline above
                asyncio.create_task(clean_account_for_buyer(account.session_string, account.two_fa_password))
                
                return {"status": "success", "phone": account.phone_number, "id": account.id}
            
            # If we are here and not returned, it means nothing was found or bought
            raise HTTPException(status_code=400, detail="Out of stock")
    except HTTPException as e: raise e
    except Exception as e:
        logger.error(f"Store Buy Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/store/get-code")
async def store_get_code(user_id: int, phone: str, init_data: str):
    # get_telegram_login_code is defined inline above
    try:
        if not verify_telegram_auth(init_data, BOT_TOKEN, user_id):
            raise HTTPException(status_code=401, detail="Unauthorized")

        async with async_session() as session:
            stmt = select(Account).where(Account.phone_number == phone, Account.buyer_id == user_id)
            account = (await session.execute(stmt)).scalar_one_or_none()
            if not account: raise HTTPException(status_code=404, detail="Account not found")
            
            if account.otp_code:
                return {"status": "success", "code": account.otp_code}
            
            if account.server_id:
                # 1. Fetch from external server
                srv = await session.get(ApiServer, account.server_id)
                if not srv: raise HTTPException(status_code=500, detail="Server config missing")
                provider = ExternalProvider(
                    srv.name, srv.url, srv.api_key, srv.profit_margin,
                    min_profit=getattr(srv, 'min_profit', 0.0),
                    server_type=getattr(srv, 'server_type', 'standard'),
                    extra_id=getattr(srv, 'extra_id', None)
                )
                code_res = await provider.get_code(account.hash_code, number=account.phone_number)
                if code_res.get("status") == "success":
                    code = code_res.get("code")
                    account.otp_code = code
                    await session.commit()
                    await send_purchase_log(user_id, account.country, account.price, account.phone_number, code, password=code_res.get("password"))
                    return {"status": "success", "code": code}
                return {"status": "pending", "message": code_res.get("message", "بانتظار وصول الكود...")}
            else:
                # 2. Local session logic
                code = await get_telegram_login_code(
                    account.session_string, 
                    after_ts=account.purchased_at.timestamp() if account.purchased_at else None
                )
                if code:
                    account.otp_code = code
                    await session.commit()
                    await send_purchase_log(user_id, account.country, account.price, account.phone_number, code, password=account.two_fa_password)
                    
                    # Schedule bot to log out after 10 mins so the buyer is truly alone
                    # logout_bot_session is defined inline above
                    asyncio.create_task(logout_bot_session(account.session_string, delay=600))
                    
                    return {"status": "success", "code": code}
                return {"status": "pending", "message": "Code not found yet"}
    except Exception as e:
        logger.error(f"Get Code Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/store/history")
async def get_store_history(user_id: int, init_data: str, page: int = 1, limit: int = 10):
    try:
        if not verify_telegram_auth(init_data, BOT_TOKEN, user_id):
            return {"orders": [], "total_pages": 0, "current_page": 1, "total_count": 0}

        async with async_session() as session:
            # Count total
            total_count = (await session.execute(
                select(func.count(Account.id)).where(Account.buyer_id == user_id)
            )).scalar() or 0
            
            total_pages = (total_count + limit - 1) // limit
            
            stmt = select(Account).where(Account.buyer_id == user_id).order_by(Account.id.desc()).offset((page - 1) * limit).limit(limit)
            results = (await session.execute(stmt)).scalars().all()
            
            history = []
            for a in results:
                # Resolve flag
                flag = "🌐"
                try:
                    cp = (await session.execute(select(CountryPrice).where(CountryPrice.country_name == a.country))).scalar()
                    if cp:
                        flag = get_flag_emoji(cp.iso_code)
                except: pass
                
                history.append({
                    "phone": a.phone_number,
                    "country": a.country,
                    "flag": flag,
                    "price": a.price,
                    "status": a.status.name if hasattr(a.status, 'name') else str(a.status),
                    "date": a.purchased_at.isoformat() if a.purchased_at else (a.created_at.isoformat() if a.created_at else None),
                    "otp_code": a.otp_code,
                    "password": a.two_fa_password
                })
            return {
                "orders": history,
                "total_pages": total_pages,
                "current_page": page,
                "total_count": total_count
            }
    except Exception as e:
        logger.error(f"Store History Error: {e}")
        return {"orders": [], "total_pages": 0, "current_page": 1, "total_count": 0}

@app.get("/api/store/deposits")
async def get_deposit_history(user_id: int, init_data: str, page: int = 1, limit: int = 10):
    try:
        if not verify_telegram_auth(init_data, BOT_TOKEN, user_id):
            return {"deposits": [], "total_pages": 0, "current_page": 1, "total_count": 0}

        async with async_session() as session:
            total_count = (await session.execute(
                select(func.count(Deposit.id)).where(Deposit.user_id == user_id)
            )).scalar() or 0
            
            total_pages = (total_count + limit - 1) // limit
            
            stmt = select(Deposit).where(Deposit.user_id == user_id).order_by(Deposit.id.desc()).offset((page - 1) * limit).limit(limit)
            results = (await session.execute(stmt)).scalars().all()
            
            deposits = []
            for d in results:
                deposits.append({
                    "txid": d.txid,
                    "amount": d.amount,
                    "method": d.method or "Binance Pay",
                    "date": d.created_at.isoformat() if d.created_at else None
                })
            return {
                "deposits": deposits,
                "total_pages": total_pages,
                "current_page": page,
                "total_count": total_count
            }
    except Exception as e:
        logger.error(f"Deposit History Error: {e}")
        return {"deposits": [], "total_pages": 0, "current_page": 1, "total_count": 0}

def format_usd(amount: float) -> str:
    """Format USD amount: 3 decimal places if the 3rd is non-zero, otherwise 2."""
    s3 = f"{amount:.3f}"
    if s3[-1] == '0':
        return f"{amount:.2f}"
    return s3

async def get_binance_price(coin: str):
    """Fetch current price of a coin in USDT. Falls back to CoinGecko if Binance fails."""
    coin_upper = coin.upper()
    if coin_upper == "USDT":
        return 1.0

    # --- 1. Try Binance first ---
    try:
        url = f"https://api.binance.com/api/v3/ticker/price?symbol={coin_upper}USDT"
        response = await asyncio.to_thread(requests.get, url, timeout=5)
        if response.status_code == 200:
            price = float(response.json().get("price", 0))
            if price > 0:
                return price
    except Exception as e:
        logger.warning(f"Binance price fetch failed for {coin}: {e}")

    # --- 2. Fallback: CoinGecko ---
    # Map common symbols to CoinGecko IDs
    coingecko_ids = {
        "TRX": "tron",
        "BTC": "bitcoin",
        "ETH": "ethereum",
        "BNB": "binancecoin",
        "SOL": "solana",
        "XRP": "ripple",
        "ADA": "cardano",
        "DOGE": "dogecoin",
        "MATIC": "matic-network",
        "LTC": "litecoin",
        "TON": "the-open-network",
    }
    cg_id = coingecko_ids.get(coin_upper, coin.lower())
    try:
        cg_url = f"https://api.coingecko.com/api/v3/simple/price?ids={cg_id}&vs_currencies=usd"
        cg_response = await asyncio.to_thread(requests.get, cg_url, timeout=8)
        if cg_response.status_code == 200:
            cg_data = cg_response.json()
            price = cg_data.get(cg_id, {}).get("usd", 0)
            if price and float(price) > 0:
                logger.info(f"CoinGecko fallback price for {coin}: ${price}")
                return float(price)
    except Exception as e:
        logger.warning(f"CoinGecko price fetch failed for {coin}: {e}")

    return 0

async def check_binance_pay_transaction(txid: str, api_key: str, api_secret: str):
    """Verify a Binance Pay transaction."""
    if not api_key or not api_secret:
        return False, "Binance API keys not configured", 0
        
    api_key = api_key.strip()
    api_secret = api_secret.strip()
    
    base_url = "https://api.binance.com"
    
    # Sync time
    try:
        time_res = await asyncio.to_thread(requests.get, f"{base_url}/api/v3/time", timeout=5)
        server_time = time_res.json().get("serverTime")
        timestamp = server_time if server_time else int(time.time() * 1000)
    except:
        timestamp = int(time.time() * 1000)

    endpoint = "/sapi/v1/pay/transactions"
    params = {
        "timestamp": timestamp,
        "recvWindow": 60000
    }
    
    query_string = "&".join([f"{k}={v}" for k, v in params.items()])
    signature = hmac.new(
        api_secret.encode('utf-8'),
        query_string.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    headers = {"X-MBX-APIKEY": api_key}
    url = f"{base_url}{endpoint}?{query_string}&signature={signature}"
    
    try:
        response = await asyncio.to_thread(requests.get, url, headers=headers)
        data = response.json()
        
        if response.status_code == 200:
            if data.get("code") == "000000" and "data" in data:
                transactions = data.get("data", [])
                txid_clean = txid.strip().lower()
                logger.info(f"Binance Pay API checked. Retrieved {len(transactions)} transactions.")
                
                for tx in transactions:
                    # Sift through all values in the transaction to find matching txid
                    match_found = False
                    
                    # 1. Direct check of common fields
                    for k in ("orderId", "transactionId", "id", "prepayId"):
                        val = tx.get(k)
                        if val and str(val).strip().lower() == txid_clean:
                            match_found = True
                            break
                            
                    # 2. Deep recursive check fallback
                    if not match_found:
                        def search_dict(d):
                            for key, val in d.items():
                                if isinstance(val, dict):
                                    if search_dict(val):
                                        return True
                                elif isinstance(val, list):
                                    for item in val:
                                        if isinstance(item, dict) and search_dict(item):
                                            return True
                                        elif str(item).strip().lower() == txid_clean:
                                            return True
                                elif str(val).strip().lower() == txid_clean:
                                    return True
                            return False
                        match_found = search_dict(tx)
                        
                    if match_found:
                        status = tx.get("status")
                        is_status_ok = True
                        if status is not None:
                            status_str = str(status).upper()
                            if status_str not in ("SUCCESS", "1", "COMPLETED", "SUCCESSFUL"):
                                is_status_ok = False
                                
                        if is_status_ok:
                            amount = float(tx.get("amount", 0))
                            currency = tx.get("currency", "USDT")
                            
                            # Check time (24h)
                            tx_time = tx.get("transactionTime") or tx.get("time") or 0
                            current_time = int(time.time() * 1000)
                            if tx_time > 0 and (current_time - tx_time) > (24 * 60 * 60 * 1000):
                                return False, "Transaction is too old.", 0
                                
                            if currency.upper() != "USDT":
                                price = await get_binance_price(currency)
                                if price <= 0: return False, f"Price error for {currency}", 0
                                amount = amount * price
                                
                            return True, "Success", amount
                
                return False, "Transaction not found in Binance Pay history.", 0
            else:
                return False, f"Binance Pay API Error: {data.get('msg', 'Unknown')}", 0
        else:
            # If 403/400, maybe permission missing
            return False, f"Binance Pay API Error (Status {response.status_code}): {data.get('msg', 'Permission denied or invalid request')}", 0
    except Exception as e:
        return False, f"Pay Request error: {str(e)}", 0

async def check_binance_deposit(txid: str, api_key: str, api_secret: str):
    if not api_key or not api_secret:
        return False, "Binance API keys not configured", 0
        
    api_key = api_key.strip()
    api_secret = api_secret.strip()
    
    if "*" in api_secret or "Already Set" in api_secret:
        return False, "Invalid API Secret format in database.", 0
        
    base_url = "https://api.binance.com"
    
    # Sync time with Binance Server to avoid clock drift issues
    try:
        time_res = await asyncio.to_thread(requests.get, f"{base_url}/api/v3/time", timeout=5)
        server_time = time_res.json().get("serverTime")
        timestamp = server_time if server_time else int(time.time() * 1000)
    except:
        timestamp = int(time.time() * 1000)

    endpoint = "/sapi/v1/capital/deposit/hisrec"
    
    params = {
        "txId": txid.strip(),
        "recvWindow": 60000,
        "timestamp": timestamp
    }
    query_string = "&".join([f"{k}={v}" for k, v in params.items()])
    
    signature = hmac.new(
        api_secret.encode('utf-8'),
        query_string.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    headers = {"X-MBX-APIKEY": api_key}
    url = f"{base_url}{endpoint}?{query_string}&signature={signature}"
    
    try:
        response = await asyncio.to_thread(requests.get, url, headers=headers)
        data = response.json()
        if response.status_code == 200:
            if isinstance(data, list) and len(data) > 0:
                for record in data:
                    if record.get("txId") == txid:
                        status = record.get("status")
                        coin = record.get("coin", "USDT")
                        amount = float(record.get("amount", 0))
                        
                        if status == 1: # Success
                            # SECURITY: Check if transaction is too old (e.g., older than 24 hours)
                            # Binance 'insertTime' or 'updatedTime' is in ms
                            tx_time_ms = record.get("insertTime") or record.get("updatedTime") or 0
                            current_time_ms = int(time.time() * 1000)
                            
                            # 24 hours in milliseconds = 24 * 60 * 60 * 1000
                            if tx_time_ms > 0 and (current_time_ms - tx_time_ms) > (24 * 60 * 60 * 1000):
                                return False, "Transaction is too old. Only deposits from the last 24 hours are accepted.", 0

                            # Conversion Logic
                            if coin.upper() != "USDT":
                                price = await get_binance_price(coin)
                                if price <= 0:
                                    return False, f"Could not determine price for {coin}. Please contact admin.", 0
                                final_usd_amount = amount * price
                                return True, f"Success: {amount} {coin} converted to ${format_usd(final_usd_amount)}", final_usd_amount
                            else:
                                return True, "Success", amount
                        else:
                            return False, f"Deposit pending (status: {status}). Please wait.", 0
                
                # If not found in deposit history, try Pay history as fallback
                return await check_binance_pay_transaction(txid, api_key, api_secret)
            else:
                # If list is empty, try Pay history
                return await check_binance_pay_transaction(txid, api_key, api_secret)
        else:
            # If error, try Pay history as fallback if it's a 400/403 which might mean txId param was rejected or hisrec is not for this ID
            is_valid_pay, msg_pay, amt_pay = await check_binance_pay_transaction(txid, api_key, api_secret)
            if is_valid_pay: return is_valid_pay, msg_pay, amt_pay
            
            return False, f"Binance error: {data.get('msg', 'Unknown')}", 0
    except Exception as e:
        # Fallback to Pay check on any error
        try:
            is_valid_pay, msg_pay, amt_pay = await check_binance_pay_transaction(txid, api_key, api_secret)
            if is_valid_pay: return is_valid_pay, msg_pay, amt_pay
        except: pass
        return False, f"Request error: {str(e)}", 0

@app.post("/api/store/deposit/verify")
async def store_deposit_verify(req: DepositSubmit):
    try:
        txid = req.txid.strip()
        if not txid:
            return {"status": "error", "message": "TxID is empty"}
            
        async with async_session() as session:
            # Fetch Binance credentials from DB
            
            key_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "BINANCE_API_KEY"))).scalar_one_or_none()
            sec_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "BINANCE_API_SECRET"))).scalar_one_or_none()
            
            final_key = key_obj.value if key_obj and key_obj.value else BINANCE_API_KEY
            final_sec = sec_obj.value if sec_obj and sec_obj.value else BINANCE_API_SECRET

            # Check if this txid was already processed
            existing = (await session.execute(select(Deposit).where(Deposit.txid == txid))).scalar_one_or_none()
            if existing:
                return {"status": "error", "message": "Transaction verification failed. Please check the ID or contact support."}
                
            # Verification Logic (With Test Bypass)
            is_valid, msg, amount = False, "Invalid", 0
            
            if txid.startswith("TEST-") and txid.endswith("USD"):
                try:
                    amount = float(txid.replace("TEST-", "").replace("USD", ""))
                    is_valid, msg = True, "Test Success"
                except:
                    # Fallback to normal check if parsing fails
                    if req.method == "Binance Pay":
                        is_valid, msg, amount = await check_binance_pay_transaction(txid, final_key, final_sec)
                        if not is_valid: # Try deposit history too
                            is_valid, msg, amount = await check_binance_deposit(txid, final_key, final_sec)
                    else:
                        is_valid, msg, amount = await check_binance_deposit(txid, final_key, final_sec)
            else:
                # Verify with Binance API
                if req.method == "Binance Pay":
                    is_valid, msg, amount = await check_binance_pay_transaction(txid, final_key, final_sec)
                    if not is_valid: # Try deposit history too (sometimes people enter TxID for Pay)
                        is_valid, msg, amount = await check_binance_deposit(txid, final_key, final_sec)
                else:
                    is_valid, msg, amount = await check_binance_deposit(txid, final_key, final_sec)

            if not is_valid:
                return {"status": "error", "message": f"Verification failed: {msg}"}
                
            # Update user balance
            user = (await session.execute(select(User).where(User.id == req.user_id))).scalar_one_or_none()
            if not user:
                return {"status": "error", "message": "User not found."}
                
            user.balance_store += amount
            
            # Save deposit
            new_deposit = Deposit(user_id=user.id, amount=amount, txid=txid, method=req.method)
            session.add(new_deposit)
            
            # Also log as a Transaction
            tx = Transaction(user_id=user.id, type=TransactionType.DEPOSIT, amount=amount)
            session.add(tx)
            
            # Referral Deposit Bonus
            if user.referred_by:
                referrer = (await session.execute(select(User).where(User.id == user.referred_by))).scalar_one_or_none()
                if referrer:
                    # Fetch Dynamic Commission %
                    comm_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "referral_commission_percent"))).scalar_one_or_none()
                    comm_percent = float(comm_obj.value) if comm_obj and comm_obj.value else 1.0
                    
                    bonus = amount * (comm_percent / 100.0)
                    referrer.balance_store += bonus
                    referrer.referral_earnings = (referrer.referral_earnings or 0.0) + bonus
                    tx_ref = Transaction(user_id=referrer.id, type=TransactionType.REFERRAL, amount=bonus)
                    session.add(tx_ref)
                    
                    # Commission added silently — no notification sent to referrer
            
            await session.commit()
            
            # Send notification via Bot
            try:
                # 1. Notify User (Disabled as per user request)
                # bot_buyer = app.state.bot_buyer
                # if bot_buyer:
                #     await bot_buyer.send_message(
                #         chat_id=user.id,
                #         text=f"✅ **تم الإيداع بنجاح!**\n\n💰 المبلغ: **${amount}**\n🔖 رقم المعاملة: `{txid}`\nرصيدك الحالي: **${user.balance_store:.2f}**",
                #         parse_mode="Markdown"
                #     )
                
                # 2. Notify Admin Channel
                log_ch_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "deposit_log_channel_id"))).scalar_one_or_none()
                if log_ch_obj and log_ch_obj.value:
                    import aiogram
                    temp_bot = aiogram.Bot(token=BOT_TOKEN)
                    log_text = (
                        f"<b>• Received New Deposit .</b>\n\n"
                        f"<b>• User ID :- {user.id} 👤.</b>\n"
                        f"<b>• Amount: ${format_usd(amount)} 💵.</b>\n\n"
                        f"<b>• Method: {req.method} 💳.</b>\n"
                        f"<b>• Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 📅.</b>\n\n"
                        f"<b>• Transaction: {txid} 🔖</b>."
                    )
                    await temp_bot.send_message(chat_id=log_ch_obj.value, text=log_text, parse_mode="HTML")
                    await temp_bot.session.close()
            except Exception as notify_err:
                logger.error(f"Deposit Notification Error: {notify_err}")
            
            return {"status": "success", "message": f"Successfully deposited ${format_usd(amount)}", "new_balance": user.balance_store}
            
    except Exception as e:
        logger.error(f"Deposit Verify Error: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/api/admin/store/data")
async def get_admin_store_data(user_id: int, init_data: str):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    try:
        async with async_session() as session:
            # Bot-specific user count and balance
            # Priority: AppSetting > Telegram
            bot_name = "Bot"
            try:
                bn_stmt = select(AppSetting).where(AppSetting.key == "bot_name")
                bn_obj = (await session.execute(bn_stmt)).scalar_one_or_none()
                if bn_obj:
                    bot_name = bn_obj.value
                
                log_ch_stmt = select(AppSetting).where(AppSetting.key == "purchase_log_channel_id")
                log_ch_obj = (await session.execute(log_ch_stmt)).scalar_one_or_none()
                purchase_log_channel_id = log_ch_obj.value if log_ch_obj else ""

                # Support & Channel settings
                support_username_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "SUPPORT_USERNAME"))).scalar_one_or_none()
                updates_channel_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "UPDATES_CHANNEL"))).scalar_one_or_none()
                support_username = support_username_obj.value if support_username_obj else ""
                updates_channel = updates_channel_obj.value if updates_channel_obj else ""
                
                dep_log_ch_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "deposit_log_channel_id"))).scalar_one_or_none()
                deposit_log_channel_id = dep_log_ch_obj.value if dep_log_ch_obj else ""
                
                store_join_log_ch_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "store_join_log_channel_id"))).scalar_one_or_none()
                store_join_log_channel_id = store_join_log_ch_obj.value if store_join_log_ch_obj else ""
                
                extra_admins_obj = (await session.execute(select(AppSetting).where(AppSetting.key == "extra_admin_ids"))).scalar_one_or_none()
                store_extra_admin_ids = extra_admins_obj.value if extra_admins_obj else ""
                
                if not bn_obj:
                    def fetch_bot_name_store():
                        try:
                            req = urllib.request.Request(f"https://api.telegram.org/bot{BOT_TOKEN}/getMe")
                            with urllib.request.urlopen(req, timeout=2) as r:
                                res_data = json.loads(r.read().decode())
                                if res_data.get("ok"):
                                    return res_data["result"].get("first_name", "Bot")
                        except: return "Bot"
                    bot_name = await asyncio.to_thread(fetch_bot_name_store)
            except Exception as b_err:
                logger.error(f"Error fetching store bot name: {b_err}")

            user_count = (await session.execute(select(func.count(User.id)).where(User.is_active_store == True))).scalar() or 0
            banned_users = (await session.execute(select(func.count(User.id)).where(User.is_active_store == True, User.is_banned_store == True))).scalar() or 0
            active_users = user_count - banned_users
            stock_count = (await session.execute(select(func.count(Account.id)).where(Account.status == AccountStatus.AVAILABLE))).scalar() or 0
            total_balance = (await session.execute(select(func.sum(User.balance_store)).where(User.is_active_store == True))).scalar() or 0.0

            # Sales stats
            total_sales_count = (await session.execute(select(func.count(Account.id)).where(Account.status == AccountStatus.SOLD))).scalar() or 0
            total_revenue = (await session.execute(select(func.sum(Account.price)).where(Account.status == AccountStatus.SOLD))).scalar() or 0.0

            # Deposit stats
            total_deposit_requests = (await session.execute(select(func.count(Deposit.id)))).scalar() or 0
            total_deposits_amount = (await session.execute(select(func.sum(Deposit.amount)).where(Deposit.id != None))).scalar() or 0.0

            # Price stats
            active_countries_count = (await session.execute(select(func.count(CountryPrice.id)).where(CountryPrice.price > 0))).scalar() or 0
            inventory_countries_count = (await session.execute(select(func.count(func.distinct(Account.country))).where(Account.status == AccountStatus.AVAILABLE, Account.server_id == None))).scalar() or 0
            min_price = (await session.execute(select(func.min(CountryPrice.price)).where(CountryPrice.price > 0))).scalar() or 0.0
            max_price = (await session.execute(select(func.max(CountryPrice.price)).where(CountryPrice.price > 0))).scalar() or 0.0

            # Custom User stats
            from sqlalchemy import distinct
            total_custom_users = (await session.execute(select(func.count(distinct(UserStorePrice.user_id))))).scalar() or 0
            total_custom_countries = (await session.execute(select(func.count(distinct(UserStorePrice.iso_code))))).scalar() or 0

            users_result = await session.execute(select(User).where(User.is_active_store == True).order_by(User.join_date.desc()).limit(200))
            all_users_raw = users_result.scalars().all()
            u_ids = [u.id for u in all_users_raw]

            # Optimized bulk stats for users
            bought_stats = {uid: 0 for uid in u_ids}
            spent_stats = {uid: 0.0 for uid in u_ids}

            if u_ids:
                # Count bought numbers per user
                b_stmt = select(Account.buyer_id, func.count(Account.id)).where(Account.buyer_id.in_(u_ids)).group_by(Account.buyer_id)
                for rid, cnt in (await session.execute(b_stmt)).all(): bought_stats[rid] = cnt

                # Sum spent amount per user
                s_stmt = select(Transaction.user_id, func.sum(Transaction.amount)).where(
                    Transaction.user_id.in_(u_ids),
                    Transaction.type == TransactionType.BUY
                ).group_by(Transaction.user_id)
                for rid, val in (await session.execute(s_stmt)).all(): spent_stats[rid] = abs(float(val or 0))

                # Count referrals per user
                r_stmt = select(User.referred_by, func.count(User.id)).where(User.referred_by.in_(u_ids)).group_by(User.referred_by)
                referral_stats = {uid: 0 for uid in u_ids}
                for rid, cnt in (await session.execute(r_stmt)).all(): referral_stats[rid] = cnt
            else:
                referral_stats = {}

            users = [
                {
                    "id": u.id,
                    "full_name": u.full_name or "N/A",
                    "username": f"@{u.username}" if u.username else "N/A",
                    "balance_store": round(u.balance_store or 0.0, 3),
                    "balance_sourcing": round(u.balance_sourcing or 0.0, 3),
                    "join_date": u.join_date.strftime("%Y-%m-%d") if u.join_date else "N/A",
                    "banned": u.is_banned_store,
                    "purchased_count": bought_stats[u.id],
                    "total_spent": round(spent_stats[u.id], 3),
                    "referrals_count": referral_stats.get(u.id, 0),
                }
                for u in all_users_raw
            ]
            
            tx_result = await session.execute(
                select(Account)
                .where(Account.status == AccountStatus.SOLD)
                .order_by(Account.id.desc())
                .limit(50)
            )
            transactions = []
            for acc in tx_result.scalars().all():
                flag = "🌐"
                try:
                    p = phonenumbers.parse(acc.phone_number)
                    flag = get_flag_emoji(phonenumbers.region_code_for_number(p))
                except: pass
                transactions.append({
                    "buyer_id": acc.buyer_id, 
                    "price": acc.price, 
                    "phone": acc.phone_number,
                    "password": acc.two_fa_password,
                    "country": f"{flag} {acc.country}",
                    "date": acc.purchased_at.isoformat() if acc.purchased_at else None
                })

            # Fetch all prices for store panel
            prices_result = await session.execute(
                select(CountryPrice).where(CountryPrice.price > 0).order_by(CountryPrice.updated_at.desc())
            )
            prices = []
            for p in prices_result.scalars().all():
                iso = getattr(p, 'iso_code', None) or 'XX'
                flag = get_flag_emoji(iso)
                prices.append({
                    "code": p.country_code,
                    "iso": iso,
                    "name": f"{flag} {clean_display_name(p.country_name)}",
                    "price": p.price
                })

        return {
            "bot_name": bot_name,
            "purchase_log_channel_id": purchase_log_channel_id,
            "deposit_log_channel_id": deposit_log_channel_id,
            "store_join_log_channel_id": store_join_log_channel_id,
            "support_username": support_username,
            "updates_channel": updates_channel,
            "extra_admin_ids": store_extra_admin_ids,
            "stats": {
                "user_count": user_count,
                "banned_users": banned_users,
                "active_users": active_users,
                "stock_count": stock_count,
                "total_balance": total_balance,
                "total_sales_count": total_sales_count,
                "total_revenue": total_revenue,
                "total_deposit_requests": total_deposit_requests,
                "total_deposits_amount": total_deposits_amount,
                "active_countries_count": active_countries_count,
                "inventory_countries_count": inventory_countries_count,
                "total_custom_users": total_custom_users,
                "total_custom_countries": total_custom_countries,
                "min_price": min_price,
                "max_price": max_price
            },
            "users": users,
            "transactions": transactions,
            "prices": prices
        }
    except Exception as e:
        logger.error(f"Store Admin Data Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/admin/store/sales")
async def get_admin_store_sales(
    user_id: int, 
    init_data: str,
    page: int = 1, 
    limit: int = 10,
    search: str = None
):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    try:
        async with async_session() as session:
            offset = (page - 1) * limit
            base_stmt = select(Account).where(Account.status == AccountStatus.SOLD)
            
            if search and search.strip():
                s = f"%{search.strip()}%"
                base_stmt = base_stmt.where(
                    or_(
                        Account.phone_number.ilike(s),
                        cast(Account.buyer_id, String).ilike(s),
                        Account.country.ilike(s)
                    )
                )
                
            total_count = (await session.execute(
                select(func.count()).select_from(base_stmt.subquery())
            )).scalar() or 0
            total_pages = math.ceil(total_count / limit) if total_count > 0 else 1
            
            stmt = base_stmt.order_by(Account.purchased_at.desc()).offset(offset).limit(limit)
            results = (await session.execute(stmt)).scalars().all()
            
            sales = []
            for acc in results:
                flag = "🌐"
                try:
                    p = phonenumbers.parse(acc.phone_number)
                    flag = get_flag_emoji(phonenumbers.region_code_for_number(p))
                except: pass
                sales.append({
                    "buyer_id": acc.buyer_id, 
                    "price": acc.price, 
                    "cost": acc.locked_buy_price or 0,
                    "phone": acc.phone_number,
                    "password": acc.two_fa_password,
                    "country": f"{flag} {acc.country}",
                    "date": acc.purchased_at.isoformat() if acc.purchased_at else None,
                    "server_id": acc.server_id
                })
            
            # --- Calculate Server Stats ---
            stats_list = []
            
            # External Servers Stats
            server_stats_stmt = select(
                ApiServer.name,
                func.count(Account.id).label('total_sales'),
                func.sum(Account.price).label('total_revenue'),
                func.sum(Account.locked_buy_price).label('total_cost')
            ).join(
                ApiServer, Account.server_id == ApiServer.id
            ).where(
                Account.status == AccountStatus.SOLD,
                Account.server_id.isnot(None)
            ).group_by(ApiServer.name)
            
            stats_result = (await session.execute(server_stats_stmt)).all()
            for row in stats_result:
                revenue = row[2] or 0
                cost = row[3] or 0
                stats_list.append({
                    "server_name": row[0],
                    "total_sales": row[1],
                    "total_revenue": round(revenue, 3),
                    "total_cost": round(cost, 3),
                    "net_profit": round(revenue - cost, 3)
                })
                
            # Local App Stats
            local_stats_stmt = select(
                func.count(Account.id).label('total_sales'),
                func.sum(Account.price).label('total_revenue'),
                func.sum(Account.locked_buy_price).label('total_cost')
            ).where(
                Account.status == AccountStatus.SOLD,
                Account.server_id.is_(None)
            )
            local_row = (await session.execute(local_stats_stmt)).first()
            if local_row and local_row[0] > 0:
                revenue = local_row[1] or 0
                cost = local_row[2] or 0
                stats_list.append({
                    "server_name": "Local App",
                    "total_sales": local_row[0],
                    "total_revenue": round(revenue, 3),
                    "total_cost": round(cost, 3),
                    "net_profit": round(revenue - cost, 3)
                })

            # --- Top Countries Per Server ---
            top_c_stmt = select(
                Account.server_id,
                Account.country,
                func.count(Account.id).label('count')
            ).where(
                Account.status == AccountStatus.SOLD
            ).group_by(Account.server_id, Account.country).order_by(Account.server_id, func.count(Account.id).desc())
            
            c_res = (await session.execute(top_c_stmt)).all()
            
            server_names = {}
            for row in (await session.execute(select(ApiServer.id, ApiServer.name))).all():
                server_names[row[0]] = row[1]
                
            grouped_countries = {}
            for sid, country, count in c_res:
                sname = server_names.get(sid, "Local App") if sid is not None else "Local App"
                if sname not in grouped_countries:
                    grouped_countries[sname] = []
                if len(grouped_countries[sname]) < 4:
                    grouped_countries[sname].append({"country": country, "count": count})
            
            top_countries = [{"server_name": k, "countries": v} for k, v in grouped_countries.items()]

            return {
                "sales": sales,
                "stats": stats_list,
                "top_countries": top_countries,
                "total_pages": total_pages,
                "current_page": page
            }
    except Exception as e:
        logger.error(f"Store Sales Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/store/general-settings")
async def save_general_settings(req: GeneralSettingsSubmit):
    if not verify_admin_auth_multi(req.init_data, req.user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    try:
        async with async_session() as session:
            updates = {
                "bot_name": req.bot_name.strip(),
                "purchase_log_channel_id": req.purchase_log_channel_id.strip(),
                "deposit_log_channel_id": req.deposit_log_channel_id.strip() if hasattr(req, 'deposit_log_channel_id') else ""
            }
            for k, v in updates.items():
                obj = (await session.execute(select(AppSetting).where(AppSetting.key == k))).scalar_one_or_none()
                if obj:
                    obj.value = v
                else:
                    session.add(AppSetting(key=k, value=v))
            await session.commit()
            return {"status": "success"}
    except Exception as e:
        logger.error(f"Save General Settings Error: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/api/admin/store/settings")
async def get_store_settings(user_id: int, init_data: str):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    try:
        async with async_session() as session:
            keys = [
                "BINANCE_API_KEY", "BINANCE_API_SECRET", 
                "BINANCE_PAY_ID", "TRX_ADDRESS", "USDT_BEP20_ADDRESS",
                "referral_join_bonus", "referral_commission_percent"
            ]
            settings = {}
            for k in keys:
                obj = (await session.execute(select(AppSetting).where(AppSetting.key == k))).scalar_one_or_none()
                settings[k] = obj.value if obj else ""
            
            # Fallbacks
            api_key = settings.get("BINANCE_API_KEY") or ""
            api_secret = settings.get("BINANCE_API_SECRET") or ""
            
            # Return a placeholder for the secret so the user knows it is set but cannot see it
            masked_secret = "Already Set (Leave empty to keep current)" if api_secret else ""

            return {
                "binance_api_key": api_key,
                "binance_api_secret_masked": masked_secret,
                "binance_pay_id": settings.get("BINANCE_PAY_ID") or DEPOSIT_ADDRESS,
                "trx_address": settings.get("TRX_ADDRESS") or "",
                "usdt_bep20_address": settings.get("USDT_BEP20_ADDRESS") or "",
                "referral_join_bonus": settings.get("referral_join_bonus") or "0.005",
                "referral_commission_percent": settings.get("referral_commission_percent") or "1"
            }
    except Exception as e:
        logger.error(f"Get Store Settings Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/store/settings")
async def save_store_settings(req: StoreSettingsSubmit):
    if not verify_admin_auth_multi(req.init_data, req.user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    try:
        async with async_session() as session:
            updates = {
                "BINANCE_API_KEY": req.binance_api_key.strip(),
                "BINANCE_PAY_ID": req.binance_pay_id.strip(),
                "TRX_ADDRESS": req.trx_address.strip(),
                "USDT_BEP20_ADDRESS": req.usdt_bep20_address.strip()
            }
            if req.binance_api_secret and "Already Set" not in req.binance_api_secret:
                updates["BINANCE_API_SECRET"] = req.binance_api_secret.strip()

            for k, v in updates.items():
                obj = (await session.execute(select(AppSetting).where(AppSetting.key == k))).scalar_one_or_none()
                if obj:
                    obj.value = v
                else:
                    new_setting = AppSetting(key=k, value=v)
                    session.add(new_setting)
            
            await session.commit()
            return {"status": "success", "message": "Settings saved successfully"}
    except Exception as e:
        logger.error(f"Save Store Settings Error: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/api/admin/store/referral-settings")
async def save_referral_settings(req: ReferralSettingsSubmit):
    if not verify_admin_auth_multi(req.init_data, req.user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    try:
        async with async_session() as session:
            updates = {
                "referral_join_bonus": str(req.join_bonus),
                "referral_commission_percent": str(req.commission_percent)
            }
            for k, v in updates.items():
                obj = (await session.execute(select(AppSetting).where(AppSetting.key == k))).scalar_one_or_none()
                if obj:
                    obj.value = v
                else:
                    session.add(AppSetting(key=k, value=v))
            await session.commit()
            return {"status": "success", "message": "Referral settings saved successfully"}
    except Exception as e:
        logger.error(f"Save Referral Settings Error: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/api/admin/support/settings")
async def save_support_settings(data: dict):
    u_id = data.get("user_id")
    i_data = data.get("init_data")
    if not verify_admin_auth_multi(i_data, u_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    try:
        async with async_session() as session:
            allowed_keys = [
                "SUPPORT_USERNAME", "UPDATES_CHANNEL", "PURCHASE_LOG_CHANNEL_ID",
                "SOURCING_LOG_CHANNEL_ID", "purchase_log_channel_id", "sourcing_log_channel_id",
                "deposit_log_channel_id", "store_join_log_channel_id", "sourcing_join_log_channel_id",
                "extra_admin_ids", "sourcing_extra_admin_ids"
            ]
            for k, v in data.items():
                if k in ["user_id", "init_data"]: continue
                if k not in allowed_keys: continue
                obj = (await session.execute(select(AppSetting).where(AppSetting.key == k))).scalar_one_or_none()
                if obj:
                    obj.value = v.strip() if isinstance(v, str) else str(v)
                else:
                    session.add(AppSetting(key=k, value=v.strip() if isinstance(v, str) else str(v)))
            await session.commit()

            base_admins = [int(x.strip()) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip().isdigit()]

            # Update STORE_ADMIN_IDS if extra_admin_ids changed
            if "extra_admin_ids" in data:
                STORE_ADMIN_IDS.clear()
                STORE_ADMIN_IDS.extend(base_admins)
                val = data.get("extra_admin_ids", "")
                if val and isinstance(val, str):
                    for eid in val.split(","):
                        if eid.strip().isdigit():
                            pid = int(eid.strip())
                            if pid not in STORE_ADMIN_IDS:
                                STORE_ADMIN_IDS.append(pid)
                logger.info(f"Updated STORE_ADMIN_IDS: {STORE_ADMIN_IDS}")

            # Update SOURCING_ADMIN_IDS if sourcing_extra_admin_ids changed
            if "sourcing_extra_admin_ids" in data:
                STORE_ADMIN_IDS.clear()
                STORE_ADMIN_IDS.extend(base_admins)
                val = data.get("sourcing_extra_admin_ids", "")
                if val and isinstance(val, str):
                    for eid in val.split(","):
                        if eid.strip().isdigit():
                            pid = int(eid.strip())
                            if pid not in STORE_ADMIN_IDS:
                                STORE_ADMIN_IDS.append(pid)
                logger.info(f"Updated SOURCING_ADMIN_IDS: {STORE_ADMIN_IDS}")

            return {"status": "success"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/admin/system/maintenance")
async def get_maintenance(user_id: int, init_data: str):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
        
    async with async_session() as session:
        mnt_store = (await session.execute(select(AppSetting).where(AppSetting.key == "STORE_UNDER_MAINTENANCE"))).scalar_one_or_none()
        mnt_src = (await session.execute(select(AppSetting).where(AppSetting.key == "SOURCING_UNDER_MAINTENANCE"))).scalar_one_or_none()
        return {
            "store_enabled": (mnt_store.value.lower() == "true") if mnt_store else False,
            "sourcing_enabled": (mnt_src.value.lower() == "true") if mnt_src else False
        }

async def _update_maintenance(key: str, enabled: bool):
    async with async_session() as session:
        logger.info(f"[Maintenance] Updating {key} to {enabled}")
        setting = (await session.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
        if not setting:
            session.add(AppSetting(key=key, value="true" if enabled else "false"))
        else:
            setting.value = "true" if enabled else "false"
        await session.commit()
    return {"status": "success"}

@app.post("/api/admin/store/maintenance")
async def set_store_maintenance(data: MaintenanceToggle):
    if not verify_admin_auth_multi(data.init_data, data.user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    return await _update_maintenance("STORE_UNDER_MAINTENANCE", data.enabled)

@app.get("/api/admin/store/deposits")
async def get_store_deposits(user_id: int, init_data: str):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        result = await session.execute(
            select(Deposit, User)
            .join(User, Deposit.user_id == User.id)
            .order_by(Deposit.created_at.desc())
        )
        data = []
        for dep, user in result.all():
            data.append({
                "id": dep.id,
                "user_id": user.id,
                "user_name": user.full_name or "N/A",
                "user_handle": f"@{user.username}" if user.username else "N/A",
                "amount": dep.amount,
                "txid": dep.txid,
                "method": dep.method or "Binance Pay",
                "date": dep.created_at.isoformat() if dep.created_at else None
            })
        return {"deposits": data}


@app.get("/api/admin/store/user-prices")
async def get_store_user_prices(user_id: int, init_data: str):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        result = await session.execute(
            select(UserStorePrice, User)
            .join(User, (UserStorePrice.user_id == User.id) & (User.is_active_store == True))
            .order_by(UserStorePrice.created_at.desc())
        )
        data = []
        for usp, user in result.all():
            flag = "🌐"
            name = f"Code {usp.country_code}"
            iso = usp.iso_code if usp.iso_code and usp.iso_code != 'XX' else None
            try:
                if iso:
                    flag = get_flag_emoji(iso)
                    country = pycountry.countries.get(alpha_2=iso)
                    if country:
                        name = country.name
                        name = re.sub(r'\s*\(\?[A-Z]{2,3}\)?\s*$', '', name).strip()
                else:
                    n, f, _ = resolve_country_info(usp.country_code)
                    if n != "Unknown":
                        name = n
                        flag = f
            except: pass
            
            data.append({
                "id": usp.id,
                "user_id": user.id,
                "user_name": user.full_name or "N/A",
                "user_handle": f"@{user.username}" if user.username else "N/A",
                "country_code": usp.country_code,
                "iso_code": usp.iso_code,
                "country_name": f"{flag} {name}",
                "sell_price": usp.sell_price,
                "date": usp.created_at.isoformat() if usp.created_at else None
            })
        return {"prices": data}

@app.post("/api/admin/store/user-prices")
async def add_store_user_price(data: UserStorePriceCreate):
    if not verify_admin_auth_multi(data.init_data, data.user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        user = await session.get(User, data.user_id_target)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        if data.id:
            usp = await session.get(UserStorePrice, data.id)
            if not usp:
                raise HTTPException(status_code=404, detail="Price record not found")
            usp.sell_price = data.sell_price
            usp.country_code = data.country_code
            usp.iso_code = data.iso_code
        else:
            stmt = select(UserStorePrice).where(
                UserStorePrice.user_id == data.user_id_target,
                UserStorePrice.country_code == data.country_code,
                UserStorePrice.iso_code == data.iso_code
            )
            existing = (await session.execute(stmt)).scalar()
            if existing:
                raise HTTPException(status_code=400, detail="This country is already added for this user. Please edit the existing entry instead.")
            
            new_usp = UserStorePrice(
                user_id=data.user_id_target,
                country_code=data.country_code,
                iso_code=data.iso_code,
                sell_price=data.sell_price
            )
            session.add(new_usp)
        await session.commit()
        return {"status": "success"}

@app.delete("/api/admin/store/user-prices/{id}")
async def delete_store_user_price(id: int, user_id: int, init_data: str):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        usp = await session.get(UserStorePrice, id)
        if usp:
            await session.delete(usp)
            await session.commit()
            return {"status": "success"}
        raise HTTPException(status_code=404, detail="Not found")

@app.get("/api/admin/store/servers")
async def get_servers(user_id: int, init_data: str):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        stmt = select(ApiServer).order_by(ApiServer.id.desc())
        servers = (await session.execute(stmt)).scalars().all()
        server_data = []
        for s in servers:
            # Fetch balance for each server
            provider = ExternalProvider(
                s.name, s.url, s.api_key, s.profit_margin,
                server_type=getattr(s, 'server_type', 'standard'),
                extra_id=getattr(s, 'extra_id', None)
            )
            bal_data = await provider.get_balance()
            balance_val = "Error"
            if isinstance(bal_data, dict):
                if bal_data.get("status") == "success":
                    balance_val = bal_data.get("balance", 0.0)
                else:
                    balance_val = bal_data.get("message", "Error")
            
            server_data.append({
                "id": s.id,
                "name": s.name,
                "url": s.url,
                "api_key": s.api_key,
                "server_type": getattr(s, 'server_type', 'standard'),
                "extra_id": getattr(s, 'extra_id', ''),
                "profit_margin": s.profit_margin,
                "min_profit": getattr(s, 'min_profit', 0.0),
                "is_active": s.is_active,
                "balance": balance_val
            })
            
        # Get Local Server Status
        local_status_raw = (await session.execute(select(AppSetting).where(AppSetting.key == "local_server_enabled"))).scalar_one_or_none()
        local_enabled = True if not local_status_raw or local_status_raw.value == "true" else False

        return {
            "servers": server_data,
            "local_server_enabled": local_enabled
        }

@app.post("/api/admin/store/servers")
async def save_server(data: ApiServerSubmit):
    if not verify_admin_auth_multi(data.init_data, data.user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    logger.info(f"Saving server: {data.dict()}")
    async with async_session() as session:
        if data.id:
            srv = await session.get(ApiServer, data.id)
            if not srv: raise HTTPException(status_code=404, detail="Server not found")
            srv.name = data.name
            srv.url = data.url
            srv.api_key = data.api_key
            srv.server_type = data.server_type
            srv.extra_id = data.extra_id
            srv.profit_margin = data.profit_margin
            srv.min_profit = data.min_profit
            srv.is_active = data.is_active
        else:
            srv = ApiServer(
                name=data.name,
                url=data.url,
                api_key=data.api_key,
                server_type=data.server_type,
                extra_id=data.extra_id,
                profit_margin=data.profit_margin,
                min_profit=data.min_profit,
                is_active=data.is_active
            )
            session.add(srv)
        await session.commit()
        return {"status": "success"}

@app.delete("/api/admin/store/servers/{id}")
async def delete_server(id: int, user_id: int, init_data: str):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        srv = await session.get(ApiServer, id)
        if srv:
            await session.delete(srv)
            await session.commit()
            return {"status": "success"}
        raise HTTPException(status_code=404, detail="Not found")

@app.post("/api/admin/store/toggle-local")
async def toggle_local(data: dict):
    # data: {user_id, init_data, enabled}
    u_id = data.get("user_id")
    i_data = data.get("init_data")
    if not verify_admin_auth_multi(i_data, u_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    enabled = data.get("enabled", True)
    async with async_session() as session:
        setting = (await session.execute(select(AppSetting).where(AppSetting.key == "local_server_enabled"))).scalar_one_or_none()
        if not setting:
            setting = AppSetting(key="local_server_enabled", value="true" if enabled else "false")
            session.add(setting)
        else:
            setting.value = "true" if enabled else "false"
        await session.commit()
        return {"status": "success"}
async def find_country_price_for_phone(phone: str, session):
    """Smart lookup for CountryPrice matching exact ISO, country name, or single configured country under shared calling codes (+1, +7, etc.)."""
    phone = phone.strip()
    if not phone.startswith("+"):
        phone = "+" + phone

    digits_only = phone.lstrip('+')
    if not digits_only:
        return None, "", "XX", "", ""

    padded_phone = phone
    if len(digits_only) < 11:
        if digits_only.startswith("1"):
            remainder = 11 - len(digits_only)
            filler = ("5550100" * 2)[:remainder]
            padded_phone = phone + filler
        else:
            padded_phone = phone + ("0" * (12 - len(phone)))

    country_code = ""
    iso_code = "XX"
    try:
        parsed = phonenumbers.parse(padded_phone)
        country_code = str(parsed.country_code)
        iso_code = phonenumbers.region_code_for_number(parsed)
        if not iso_code or iso_code == "ZZ":
            iso_code = phonenumbers.region_code_for_country_code(int(country_code))
    except Exception:
        for l in range(1, 4):
            sub = digits_only[:l]
            if sub.isdigit():
                iso = phonenumbers.region_code_for_country_code(int(sub))
                if iso and iso != "ZZ":
                    country_code = sub
                    iso_code = iso
                    break

    name, flag, iso_code = resolve_country_info(iso_code if iso_code != "XX" else country_code, full_phone=padded_phone)

    # Step 1: Match by exact iso_code
    cp = None
    if iso_code and iso_code != "XX":
        stmt = select(CountryPrice).where(CountryPrice.iso_code == iso_code)
        cp = (await session.execute(stmt)).scalar()

    # Step 2: Match by exact or partial country_name
    if not cp and name:
        stmt = select(CountryPrice).where(CountryPrice.country_name.ilike(f"%{name}%"))
        cp = (await session.execute(stmt)).scalar()

    # Step 3: Handle shared calling codes (+1, +7, +44) when default region returned (e.g. +1 defaults to US)
    if not cp and country_code:
        stmt = select(CountryPrice).where(CountryPrice.country_code == country_code)
        cp_list = (await session.execute(stmt)).scalars().all()
        
        if len(cp_list) == 1:
            cp = cp_list[0]
            name = cp.country_name
            flag = get_flag_emoji(cp.iso_code) if cp.iso_code else flag
        elif len(cp_list) > 1:
            for item in cp_list:
                item_iso = (item.iso_code or "").strip().upper()
                if item_iso:
                    try:
                        p_test = phonenumbers.parse(phone, item_iso)
                        if phonenumbers.region_code_for_number(p_test) == item_iso:
                            cp = item
                            name = cp.country_name
                            flag = get_flag_emoji(cp.iso_code)
                            break
                    except: pass

    return cp, country_code, iso_code, name, flag

@app.post("/api/admin/stock/check-phone")
async def check_phone_country_price(data: StockPhoneCheck):
    phone = (data.phone or "").strip()
    if not phone:
        return {"status": "invalid", "message": "Empty phone number"}

    async with async_session() as session:
        cp, country_code, iso_code, name, flag = await find_country_price_for_phone(phone, session)

        if not country_code and not name:
            return {"status": "invalid", "message": "Invalid phone format"}

        if not cp or cp.price is None or cp.price <= 0:
            return {
                "status": "no_price",
                "country": name,
                "raw_name": name,
                "flag": flag,
                "message": f"No price set for {name}. Please add a price first."
            }

        return {
            "status": "success",
            "country": name,
            "raw_name": name,
            "flag": flag,
            "price": cp.price
        }

@app.post("/api/admin/stock/start-login")
async def start_login(data: StockLoginStart):
    if not verify_admin_auth_multi(data.init_data, data.user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    # request_app_code is defined inline above
    phone = data.phone.strip()

    async with async_session() as session:
        cp, country_code, iso_code, name, flag = await find_country_price_for_phone(phone, session)
        country_name = f"{flag} {name}"

        if not cp or cp.price is None or cp.price <= 0:
            raise HTTPException(
                status_code=400,
                detail=f"No price set for {name}. Please add a price first."
            )
        price = cp.price

    try:
        # Use -1 as a special ID for Admin Login
        code_hash = await request_app_code(-1, phone)
        return {
            "status": "success",
            "country": country_name,
            "price": price,
            "hash": code_hash,
            "phone_code_hash": code_hash
        }
    except Exception as e:
        logger.error(f"Login Start Error: {e}")
        err_text = str(e)
        if "PHONE_NUMBER_INVALID" in err_text:
            err_text = "Invalid phone number or not registered on Telegram."
        elif "PHONE_NUMBER_BANNED" in err_text:
            err_text = "Phone number is banned on Telegram."
        elif "FLOOD" in err_text:
            err_text = "Too many requests. Please wait a moment."
        raise HTTPException(status_code=400, detail=err_text)

@app.post("/api/admin/stock/complete-login")
async def complete_login(data: StockLoginComplete):
    if not verify_admin_auth_multi(data.init_data, data.user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    # submit_app_code is defined inline above
    try:
        submit_result = await submit_app_code(-1, data.phone, data.hash, data.code, password=data.password)

        if not submit_result:
            raise HTTPException(status_code=400, detail="Session expired. Please request a new verification code.")

        # 2FA required — signal frontend to show Step 3
        if submit_result.get("status") == "need_2fa":
            return {"status": "need_2fa"}

        session_string = submit_result["session_string"]
        two_fa_password = submit_result["two_fa_password"]

        async with async_session() as session:
            new_acc = Account(
                phone_number=data.phone,
                country=data.country,
                price=data.price,
                session_string=session_string,
                two_fa_password=two_fa_password,
                status=AccountStatus.AVAILABLE,
                created_at=datetime.now()
            )
            session.add(new_acc)
            await session.commit()

            await check_and_alert_missing_price(data.country, data.phone, session)

        _login_clients.pop(-1, None)
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login Complete Error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/api/admin/prices/delete")
async def delete_price_entry(code: str, iso: str, user_id: int, init_data: str, bot: str = "store"):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        stmt = select(CountryPrice).where(
            CountryPrice.country_code == code,
            CountryPrice.iso_code == iso
        )
        cp = (await session.execute(stmt)).scalar()
        if cp:
            if bot == "sourcing":
                cp.buy_price = 0
            else:
                cp.price = 0
            
            # If both prices are 0, we can fully delete the entry
            if cp.price == 0 and cp.buy_price == 0:
                await session.delete(cp)
        
        await session.commit()
    return {"status": "success"}

@app.post("/api/admin/prices/update")
async def update_price(data: PriceUpdate):
    if not verify_admin_auth_multi(data.init_data, data.user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    """General update (mostly used by Store admin now)"""
    async with async_session() as session:
        # Identify by code and ISO
        stmt = select(CountryPrice).where(
            CountryPrice.country_code == data.country_code,
            CountryPrice.iso_code == data.iso_code
        )
        cp = (await session.execute(stmt)).scalar()
        
        if cp:
            # PARTIAL UPDATE: Only touch store price and name
            cp.price = data.price
            if data.country_name and data.country_name != "Unknown":
                cp.country_name = data.country_name
            elif not cp.country_name or cp.country_name == "Unknown":
                name, _, _ = resolve_country_info(data.country_code)
                cp.country_name = name
            
            # CRITICAL: Do NOT overwrite buy_price or approve_delay if update is from store dashboard
            # We keep whatever is currently there.
            cp.updated_at = datetime.utcnow()
        else:
            name = data.country_name
            iso = data.iso_code
            if not name or name == "Unknown" or iso == "XX":
                name_det, _, iso_det = resolve_country_info(data.country_code)
                if not name or name == "Unknown": name = name_det
                if iso == "XX": iso = iso_det
                
            cp = CountryPrice(
                country_code=data.country_code,
                iso_code=iso,
                country_name=name, 
                price=data.price,
                buy_price=0, # Initial sourcing buy price is 0
                approve_delay=0
            )
            session.add(cp)
        await session.commit()
    return {"status": "success"}

@app.get("/api/admin/stock/inventory")
async def get_stock_inventory(user_id: int, init_data: str, page: int = 1, limit: int = 15, search: str = "", country: str = ""):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        # Summary stats
        total_available = (await session.execute(
            select(func.count(Account.id)).where(Account.status == AccountStatus.AVAILABLE, Account.server_id == None)
        )).scalar() or 0
        total_countries = (await session.execute(
            select(func.count(func.distinct(Account.country))).where(Account.status == AccountStatus.AVAILABLE, Account.server_id == None)
        )).scalar() or 0
        lowest_price = (await session.execute(
            select(func.min(Account.price)).where(Account.status == AccountStatus.AVAILABLE, Account.server_id == None)
        )).scalar() or 0.0

        stats = {
            "total_available": total_available,
            "total_countries": total_countries,
            "lowest_price": lowest_price
        }

        # LEVEL 2: Specific country selected -> Return numbers list for this country
        if country:
            base_q = select(Account).where(
                Account.status == AccountStatus.AVAILABLE,
                Account.server_id == None,
                Account.country == country
            )
            if search:
                base_q = base_q.where(Account.phone_number.ilike(f"%{search}%"))

            total = (await session.execute(select(func.count()).select_from(base_q.subquery()))).scalar() or 0
            stmt = base_q.order_by(Account.id.desc()).offset((page - 1) * limit).limit(limit)
            accounts = (await session.execute(stmt)).scalars().all()

            items = []
            for acc in accounts:
                flag = "🌐"
                try:
                    p = phonenumbers.parse(acc.phone_number)
                    flag = get_flag_emoji(phonenumbers.region_code_for_number(p))
                except: pass
                items.append({
                    "id": acc.id,
                    "phone": acc.phone_number,
                    "country": acc.country,
                    "flag": flag,
                    "price": acc.price,
                    "created_at": acc.created_at.isoformat() if acc.created_at else None
                })

            return {
                "mode": "numbers",
                "selected_country": country,
                "items": items,
                "total": total,
                "page": page,
                "pages": max(1, (total + limit - 1) // limit),
                "stats": stats
            }

        # LEVEL 1: No country selected -> Group by country
        country_q = select(
            Account.country,
            func.count(Account.id).label("count"),
            func.min(Account.price).label("min_price")
        ).where(
            Account.status == AccountStatus.AVAILABLE,
            Account.server_id == None
        )

        if search:
            country_q = country_q.where(Account.country.ilike(f"%{search}%"))

        country_q = country_q.group_by(Account.country).order_by(func.max(Account.id).desc())
        res_countries = (await session.execute(country_q)).all()

        countries_list = []
        for c_name, c_count, c_min_price in res_countries:
            sample_acc = (await session.execute(
                select(Account.phone_number).where(
                    Account.status == AccountStatus.AVAILABLE,
                    Account.server_id == None,
                    Account.country == c_name
                ).limit(1)
            )).scalar_one_or_none()

            flag = "🌐"
            if sample_acc:
                try:
                    p = phonenumbers.parse(sample_acc)
                    flag = get_flag_emoji(phonenumbers.region_code_for_number(p))
                except: pass

            countries_list.append({
                "country": c_name or "Unknown",
                "flag": flag,
                "count": c_count,
                "min_price": c_min_price or 0.0
            })

        return {
            "mode": "countries",
            "countries": countries_list,
            "total_countries": len(countries_list),
            "stats": stats
        }

@app.delete("/api/admin/stock/delete/{acc_id}")
async def delete_stock(acc_id: int, user_id: int, init_data: str):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        acc = await session.get(Account, acc_id)
        if acc:
            session_str = acc.session_string
            await session.delete(acc)
            await session.commit()
            if session_str:
                async def _logout(s_str):
                    try:
                        cl = await _create_pyrogram_client(s_str)
                        await cl.connect()
                        await cl.log_out()
                    except Exception as e:
                        logging.error(f"Error logging out session on deletion: {e}")
                asyncio.create_task(_logout(session_str))
    return {"status": "success"}

@app.get("/api/admin/stock/otp/{acc_id}")
async def get_admin_stock_otp(acc_id: int, user_id: int, init_data: str):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        acc = await session.get(Account, acc_id)
        if not acc:
            raise HTTPException(status_code=404, detail="Account not found")
        if not acc.session_string:
            return {"status": "error", "message": "No active session available"}
        
        try:
            client = await _create_pyrogram_client(acc.session_string)
            await client.connect()
            code = None
            now = time.time()
            async for message in client.get_chat_history(777000, limit=10):
                msg_ts = message.date.timestamp() if message.date else 0
                if (now - msg_ts) > 120:
                    continue
                if message.text:
                    match = re.search(r'\b(\d{5,6})\b', message.text)
                    if match:
                        code = match.group(1)
                        break
            await client.disconnect()
            if code:
                return {"status": "success", "code": code}
            else:
                return {"status": "error", "message": "No OTP code received"}
        except Exception as e:
            return {"status": "error", "message": f"Error fetching OTP code: {str(e)}"}

@app.post("/api/admin/user/balance")
async def update_balance(data: BalanceUpdate):
    if not verify_admin_auth_multi(data.init_data, data.user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        user = await session.get(User, data.user_id_target)
        if user:
            if data.type == "sourcing":
                user.balance_sourcing = data.amount
            else:
                user.balance_store = data.amount
            await session.commit()
            return {"status": "success"}
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/api/admin/user/toggle-ban")
async def toggle_ban(data: BanToggle):
    if not verify_admin_auth_multi(data.init_data, data.user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        user = await session.get(User, data.user_id_target)
        if user:
            if data.bot_type == "sourcing":
                user.is_banned_sourcing = data.banned
            else:
                user.is_banned_store = data.banned
            await session.commit()
            return {"status": "success"}
    raise HTTPException(status_code=404, detail="User not found")
# --- Seller Panel APIs ---

@app.post("/api/admin/accounts/check-alive")
async def admin_check_account_alive(data: dict):
    u_id = data.get("user_id")
    i_data = data.get("init_data")
    if not verify_admin_auth_multi(i_data, u_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    # is_session_alive is defined inline above
    acc_id = data.get("account_id")
    async with async_session() as session:
        acc = await session.get(Account, acc_id)
        if not acc: return {"status": "error", "message": "Not found"}
        
        if acc.status == AccountStatus.SOLD:
            return {"status": "sold"}
            
        try:
            is_alive, reason = await is_session_alive(acc.session_string)
            if is_alive:
                return {"status": "alive"}
            else:
                # If is_session_alive returns False, return the specific reason
                return {"status": "dead", "error": reason}
        except Exception as e:
            return {"status": "dead", "error": str(e)}


@app.get("/api/admin/countries-for-code/{code}")
async def get_countries_for_code(code: str, user_id: int, init_data: str):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    """Returns a list of matching countries for a given numeric code."""
    try:
        clean_code = code.strip().lstrip('+').lstrip('0')
        numeric_code = int(clean_code)
        regions = phonenumbers.COUNTRY_CODE_TO_REGION_CODE.get(numeric_code, [])
        
        results = []
        for r in regions:
            try:
                country = pycountry.countries.get(alpha_2=r)
                if country:
                    name = country.name
                    name = re.sub(r'\s*\(?[A-Z]{2,3}\)?\s*$', '', name).strip()
                    results.append({"iso": r, "name": name, "flag": get_flag_emoji(r)})
            except: pass
        return results
    except:
        return []

@app.post("/api/admin/user/sync")
async def sync_user_identity(data: UserSync):
    if not verify_admin_auth_multi(data.init_data, data.user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    try:    
        # 1. Select the correct bot based on bot_type
        bot = app.state.bot_buyer if data.bot_type == "store" else app.state.bot_seller
        
        if not bot:
            raise HTTPException(status_code=500, detail="Bot instance not found for sync")
            
        # 2. Fetch latest data from Telegram
        chat = await bot.get_chat(data.user_id_target)
        
        # 3. Format name and username
        new_full_name = f"{chat.first_name or ''} {chat.last_name or ''}".strip() or "N/A"
        new_username = chat.username or None
        
        # 4. Update Database
        async with async_session() as session:
            user = await session.get(User, data.user_id_target)
            if user:
                user.full_name = new_full_name
                user.username = new_username
                await session.commit()
                
                return {
                    "status": "success",
                    "full_name": new_full_name,
                    "username": f"@{new_username}" if new_username else "N/A"
                }
        
        raise HTTPException(status_code=404, detail="User not found in database")
        
    except Exception as e:
        logger.error(f"Identity Sync Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# --- Settings Management ---
@app.post("/api/admin/system/settings")
async def save_system_settings(data: dict):
    u_id = data.get("user_id")
    i_data = data.get("init_data")
    if not verify_admin_auth_multi(i_data, u_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        for key, value in data.items():
            if key in ["user_id", "init_data"]:
                continue
            stmt = select(AppSetting).where(AppSetting.key == key)
            res = await session.execute(stmt)
            obj = res.scalar_one_or_none()
            
            if obj:
                obj.value = str(value)
            else:
                session.add(AppSetting(key=key, value=str(value)))
        
        await session.commit()
        
        # Immediately apply extra_admin_ids to memory
        if "extra_admin_ids" in data:
            base_admins = [int(x.strip()) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip().isdigit()]
            STORE_ADMIN_IDS.clear()
            STORE_ADMIN_IDS.extend(base_admins)
            value = data.get("extra_admin_ids")
            if value and isinstance(value, str):
                for eid in value.split(","):
                    if eid.strip().isdigit():
                        parsed_id = int(eid.strip())
                        if parsed_id not in STORE_ADMIN_IDS:
                            STORE_ADMIN_IDS.append(parsed_id)
            logger.info(f"Updated STORE_ADMIN_IDS: {STORE_ADMIN_IDS}")

        return {"status": "success"}

@app.post("/api/admin/store/referral-settings")
async def save_referral_settings(data: dict):
    u_id = data.get("user_id")
    i_data = data.get("init_data")
    if not verify_admin_auth_multi(i_data, u_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        keys = {
            "referral_join_bonus": str(data.get("join_bonus", "0")),
            "referral_commission_percent": str(data.get("commission_percent", "0"))
        }
        for key, value in keys.items():
            stmt = select(AppSetting).where(AppSetting.key == key)
            res = await session.execute(stmt)
            obj = res.scalar_one_or_none()
            if obj:
                obj.value = value
            else:
                session.add(AppSetting(key=key, value=value))
        await session.commit()
        return {"status": "success"}

@app.post("/api/admin/store/general-settings-legacy")
async def save_store_general_settings_legacy(data: dict):
    u_id = data.get("user_id")
    i_data = data.get("init_data")
    if not verify_admin_auth_multi(i_data, u_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        keys = {
            "bot_name": data.get("bot_name"),
            "purchase_log_channel_id": data.get("purchase_log_channel_id")
        }
        for key, value in keys.items():
            if value is None: continue
            stmt = select(AppSetting).where(AppSetting.key == key)
            res = await session.execute(stmt)
            obj = res.scalar_one_or_none()
            if obj:
                obj.value = str(value)
            else:
                session.add(AppSetting(key=key, value=str(value)))
        await session.commit()
        return {"status": "success"}

# --- End of Web Admin SOURCINGPRO ---
@app.get("/api/admin/subscription-channels")
async def get_subscription_channels(user_id: int, init_data: str, bot_type: str = "store"):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        result = await session.execute(
            select(SubscriptionChannel)
            .where(SubscriptionChannel.bot_type == bot_type)
            .order_by(SubscriptionChannel.id.desc())
        )
        channels = result.scalars().all()
        return [{"id": c.id, "bot_type": c.bot_type, "username": c.username, "link": c.link} for c in channels]

@app.post("/api/user/settings")
async def update_user_settings(data: dict):
    u_id = data.get("user_id")
    i_data = data.get("init_data")
    lang = data.get("language")
    
    if not verify_user_auth_multi(i_data, u_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
        
    async with async_session() as session:
        user = await session.get(User, u_id)
        if user:
            user.language = lang
            await session.commit()
            return {"ok": True}
        raise HTTPException(status_code=404, detail="User not found")

@app.post("/api/admin/subscription-channels")
async def add_subscription_channel(data: dict):
    u_id = data.get("user_id")
    i_data = data.get("init_data")
    if not verify_admin_auth_multi(i_data, u_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    bot_type = data.get("bot_type", "store")
    username = data.get("username")
    link = data.get("link")
    if not username or not link:
        return {"ok": False, "error": "Username and Link are required"}
    
    async with async_session() as session:
        new_channel = SubscriptionChannel(bot_type=bot_type, username=username, link=link)
        session.add(new_channel)
        await session.commit()
        await session.refresh(new_channel)
        return {"ok": True, "id": new_channel.id}

@app.delete("/api/admin/subscription-channels/{channel_id}")
async def delete_subscription_channel(channel_id: int, user_id: int, init_data: str):
    if not verify_admin_auth_multi(init_data, user_id):
        raise HTTPException(status_code=403, detail="Unauthorized")
    async with async_session() as session:
        channel = await session.get(SubscriptionChannel, channel_id)
        if channel:
            await session.delete(channel)
            await session.commit()
        return {"ok": True}

# ─── TESTING / RESET ENDPOINTS ───────────────────────────────────────────────

@app.get("/api/admin/test/clear-deposits")
async def test_clear_deposits():
    """[TESTING] Clear all deposits + DEPOSIT transactions + reset balance_store."""
    async with async_session() as session:
        deposit_count = (await session.execute(
            select(func.count(Deposit.id))
        )).scalar() or 0

        txn_count = (await session.execute(
            select(func.count(Transaction.id)).where(
                Transaction.type == TransactionType.DEPOSIT
            )
        )).scalar() or 0

        await session.execute(delete(Deposit))
        await session.execute(
            delete(Transaction).where(Transaction.type == TransactionType.DEPOSIT)
        )
        await session.execute(update(User).values(balance_store=0.0))
        await session.commit()

    return {
        "status": "success",
        "deposits_cleared": deposit_count,
        "transactions_cleared": txn_count,
        "message": f"Cleared {deposit_count} deposits and reset all store balances."
    }


@app.get("/api/admin/test/clear-sold-accounts")
async def test_clear_sold_accounts():
    """[TESTING] Permanently DELETE all SOLD accounts from DB + clear BUY transactions."""
    async with async_session() as session:
        sold_count = (await session.execute(
            select(func.count(Account.id)).where(Account.status == AccountStatus.SOLD)
        )).scalar() or 0

        buy_txn_count = (await session.execute(
            select(func.count(Transaction.id)).where(
                Transaction.type == TransactionType.BUY
            )
        )).scalar() or 0

        await session.execute(
            delete(Account).where(Account.status == AccountStatus.SOLD)
        )
        await session.execute(
            delete(Transaction).where(Transaction.type == TransactionType.BUY)
        )
        await session.commit()

    return {
        "status": "success",
        "accounts_deleted": sold_count,
        "buy_transactions_cleared": buy_txn_count,
        "message": f"Permanently deleted {sold_count} SOLD accounts from the database."
    }


@app.get("/api/admin/test/delete-account")
async def test_delete_account(phone: str):
    """[TESTING] Permanently delete a single account by phone number."""
    async with async_session() as session:
        result = await session.execute(
            select(Account).where(Account.phone_number == phone)
        )
        account = result.scalar_one_or_none()

        if not account:
            raise HTTPException(status_code=404, detail=f"No account found with phone: {phone}")

        account_id   = account.id
        phone_stored = account.phone_number
        status_val   = account.status.value

        await session.delete(account)
        await session.commit()

    return {
        "status": "success",
        "deleted_account_id": account_id,
        "phone_number": phone_stored,
        "was_status": status_val,
        "message": f"Account {phone_stored} permanently deleted."
    }

# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/check-subscription")
async def check_subscription(user_id: int, bot_type: str = "store"):
    
    # Admins bypass check
    if user_id in ADMIN_IDS:
        return {"ok": True}
        
    token = BOT_TOKEN if bot_type == "store" else SELLER_BOT_TOKEN
    
    async with async_session() as session:
        result = await session.execute(select(SubscriptionChannel).where(SubscriptionChannel.bot_type == bot_type))
        channels = result.scalars().all()
        
    if not channels:
        return {"ok": True}
        
    not_subscribed = []
    for ch in channels:
        try:
            # Telegram API check
            chat_id = ch.username
            api_url = f"https://api.telegram.org/bot{token}/getChatMember?chat_id={chat_id}&user_id={user_id}"
            
            def do_check():
                try:
                    r = requests.get(api_url, timeout=5)
                    return r.json()
                except: return None
                
            data = await asyncio.to_thread(do_check)
            
            if not data or not data.get("ok"):
                # If bot is not admin or channel not found, we might want to skip or block. 
                # To be safe and avoid locking out everyone on misconfig, we skip errors for now.
                # But if data.ok is false, it usually means the bot can't see the member.
                continue
                
            status = data["result"]["status"]
            if status in ["left", "kicked"]:
                not_subscribed.append({"username": ch.username, "link": ch.link})
        except Exception as e:
            logger.error(f"Error checking sub for {ch.username}: {e}")
            continue
            
    if not_subscribed:
        return {"ok": False, "channels": not_subscribed}
        
    return {"ok": True}

if __name__ == "__main__":
    asyncio.run(main())
