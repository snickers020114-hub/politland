import asyncio
import logging
import re

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import BotCommand, Message

import config
import db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("bot")

NICK_RE = re.compile(r"^[a-zA-Z0-9_]{3,16}$")
PASS_MIN = 4
PASS_MAX = 64

router = Router()


class Reg(StatesGroup):
    nickname = State()
    password = State()


class PassChange(StatesGroup):
    password = State()


def acc_info(acc):
    return (
        f"<b>Твой аккаунт</b>\n"
        f"👤 Никнейм: <code>{acc['nickname']}</code>\n"
        f"🆔 UUID: <code>{acc['uuid']}</code>\n\n"
        f"Вход в лаунчере: <b>Аккаунты</b> → <b>Войти в аккаунт</b> → никнейм и пароль."
    )


@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    acc = db.get_account_by_telegram(message.from_user.id)
    if acc is not None:
        await message.answer(
            acc_info(acc) + "\n\nЕсли хочешь новый аккаунт — используй /changepass для смены пароля.",
            parse_mode=ParseMode.HTML,
        )
        return
    await state.set_state(Reg.nickname)
    await message.answer(
        "📝 <b>Регистрация</b>\n\nВведи желаемый никнейм:\n"
        "• от 3 до 16 символов\n"
        "• только латинские буквы, цифры и <code>_</code>",
        parse_mode=ParseMode.HTML,
    )


@router.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext):
    current = await state.get_state()
    if current is None:
        await message.answer("Нечего отменять. Напиши /start для регистрации.")
        return
    await state.clear()
    await message.answer("❌ Отменено.")


@router.message(Reg.nickname, F.text)
async def reg_nickname(message: Message, state: FSMContext):
    nick = message.text.strip()
    if not NICK_RE.match(nick):
        await message.answer(
            "❌ Недопустимый никнейм.\n\n"
            "Требования:\n"
            "• от 3 до 16 символов\n"
            "• только латинские буквы, цифры и <code>_</code>\n\nПопробуй ещё раз:",
            parse_mode=ParseMode.HTML,
        )
        return
    if db.nickname_taken(nick):
        await message.answer("❌ Этот никнейм уже занят. Попробуй другой:")
        return
    await state.update_data(nickname=nick)
    await state.set_state(Reg.password)
    await message.answer(
        f"✅ Никнейм <b>{nick}</b> свободен.\n\n"
        f"🔑 Теперь придумай пароль:\n"
        f"• от {PASS_MIN} до {PASS_MAX} символов\n"
        f"• можно любые символы",
        parse_mode=ParseMode.HTML,
    )


@router.message(Reg.password, F.text)
async def reg_password(message: Message, state: FSMContext):
    password = message.text
    if not (PASS_MIN <= len(password) <= PASS_MAX):
        await message.answer(
            f"❌ Пароль должен быть от {PASS_MIN} до {PASS_MAX} символов. Попробуй ещё раз:"
        )
        return
    data = await state.get_data()
    nickname = data.get("nickname")
    acc = db.create_account(nickname, password, telegram_id=message.from_user.id)
    if acc is None:
        await message.answer("❌ Не удалось создать аккаунт. Попробуй снова: /start")
        await state.clear()
        return
    await state.clear()
    await message.answer(
        "✅ <b>Аккаунт создан!</b>\n\n"
        f"👤 Никнейм: <code>{acc['nickname']}</code>\n"
        f"🆔 UUID: <code>{acc['uuid']}</code>\n\n"
        "Запомни никнейм и пароль — они нужны для входа.\n\n"
        "Как войти в игру:\n"
        "1. Открой лаунчер <b>Polit Land</b>\n"
        "2. Вкладка «Аккаунты»\n"
        "3. Кнопка «Войти в аккаунт»\n"
        "4. Введи никнейм и пароль",
        parse_mode=ParseMode.HTML,
    )


@router.message(Command("info"))
async def cmd_info(message: Message, state: FSMContext):
    acc = db.get_account_by_telegram(message.from_user.id)
    if acc is None:
        await message.answer("У тебя пока нет аккаунта. Напиши /start для регистрации.")
        return
    await message.answer(acc_info(acc), parse_mode=ParseMode.HTML)


@router.message(Command("changepass"))
async def cmd_changepass(message: Message, state: FSMContext):
    acc = db.get_account_by_telegram(message.from_user.id)
    if acc is None:
        await message.answer("У тебя пока нет аккаунта. Напиши /start для регистрации.")
        return
    await state.set_state(PassChange.password)
    await message.answer(
        f"🔑 Введи новый пароль (от {PASS_MIN} до {PASS_MAX} символов):"
    )


@router.message(PassChange.password, F.text)
async def passchange_password(message: Message, state: FSMContext):
    password = message.text
    if not (PASS_MIN <= len(password) <= PASS_MAX):
        await message.answer(
            f"❌ Пароль должен быть от {PASS_MIN} до {PASS_MAX} символов. Попробуй ещё раз:"
        )
        return
    acc = db.get_account_by_telegram(message.from_user.id)
    if acc is None:
        await state.clear()
        await message.answer("Аккаунт не найден. Напиши /start.")
        return
    db.change_password(acc["id"], password)
    db.delete_sessions_for_account(acc["id"])
    await state.clear()
    await message.answer(
        f"✅ Пароль для <b>{acc['nickname']}</b> изменён.", parse_mode=ParseMode.HTML
    )


@router.message(Command("help"))
async def cmd_help(message: Message):
    await message.answer(
        "🤖 <b>Polit Land — бот регистрации</b>\n\n"
        "/start — регистрация нового аккаунта\n"
        "/info — данные моего аккаунта\n"
        "/changepass — сменить пароль\n"
        "/cancel — отменить текущее действие\n\n"
        "После регистрации войди в лаунчере: Аккаунты → Войти в аккаунт.",
        parse_mode=ParseMode.HTML,
    )


@router.message()
async def fallback(message: Message):
    await message.answer("Напиши /start для регистрации или /help для списка команд.")


async def main():
    token = config.get("bot_token")
    if not token or token.startswith("PASTE"):
        log.error("Bot token is empty. Fill it in config.json (bot_token).")
        return
    bot = Bot(token=token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    await bot.set_my_commands(
        [
            BotCommand(command="start", description="Регистрация"),
            BotCommand(command="info", description="Мой аккаунт"),
            BotCommand(command="changepass", description="Сменить пароль"),
            BotCommand(command="help", description="Помощь"),
            BotCommand(command="cancel", description="Отменить"),
        ]
    )
    dp = Dispatcher()
    dp.include_router(router)
    log.info("Bot started (polling)...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass