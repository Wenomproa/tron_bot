import telebot
from mnemonic import Mnemonic
import hashlib
import requests
import base58

TOKEN = '7919640577:AAE-6M9yer-d8vGnsEXzrNxLNfkWBkrwZdw'  # Инҷо токени ботатонро гузоред
bot = telebot.TeleBot(TOKEN)

def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()

def generate_btc_address(seed_bytes):
    pubkey = b'\x04' + seed_bytes[:64]
    h160 = ripemd160(sha256(pubkey))
    addr = b'\x00' + h160
    checksum = sha256(sha256(addr))[:4]
    return base58.b58encode(addr + checksum).decode()

def get_btc_balance(address):
    try:
        url = f"https://blockchain.info/q/addressbalance/{address}"
        res = requests.get(url, timeout=10)
        return int(res.text) / 1e8
    except:
        return 0

def get_eth_balance(address):
    try:
        url = f"https://api.blockcypher.com/v1/eth/main/addrs/{address}/balance"
        res = requests.get(url, timeout=10).json()
        return res.get("balance", 0) / 1e18
    except:
        return 0

def get_trx_balance(address):
    try:
        url = f"https://apilist.tronscanapi.com/api/account?address={address}"
        res = requests.get(url, timeout=10).json()
        balance = res.get('balance', 0)
        return float(balance) / 1e6
    except:
        return 0

def get_ton_balance(address):
    try:
        url = f"https://toncenter.com/api/v2/getAddressBalance?address={address}"
        res = requests.get(url, timeout=10).json()
        return int(res['result']) / 1e9
    except:
        return 0

def get_usdt_tron_balance(address):
    try:
        url = f"https://apilist.tronscanapi.com/api/token/holder/holders?address={address}&token=1002000"
        res = requests.get(url, timeout=10).json()
        balance = 0
        for token_info in res.get('data', []):
            if token_info.get('tokenName') == 'Tether USD':
                balance = float(token_info.get('balance', 0))
                break
        return balance / 1e6
    except:
        return 0

@bot.message_handler(content_types=['document'])
def handle_file(message):
    file_info = bot.get_file(message.document.file_id)
    downloaded = bot.download_file(file_info.file_path)
    filename = message.document.file_name

    with open(filename, 'wb') as f:
        f.write(downloaded)

    with open(filename, 'r') as f:
        seeds = f.read().splitlines()

    mnemo = Mnemonic("english")
    found = []
    for seed in seeds:
        try:
            if not mnemo.check(seed):
                continue

            seed_bytes = hashlib.pbkdf2_hmac("sha512", seed.encode(), b'mnemonic', 2048)

            btc_addr = generate_btc_address(seed_bytes)
            btc_bal = get_btc_balance(btc_addr)
            eth_bal = get_eth_balance(btc_addr)  # Эҳтимол суроғаи ETH алоҳида лозим аст
            trx_bal = get_trx_balance(btc_addr)  # Ҳамин тавр суроғаи TRX лозим аст
            ton_bal = get_ton_balance(btc_addr)
            usdt_bal = get_usdt_tron_balance(btc_addr)

            total = btc_bal + eth_bal + trx_bal + ton_bal + usdt_bal
            if total > 0:
                res = f"✅ Миқдори пул ёфт шуд:\nSeed: {seed}\nBTC: {btc_addr} = {btc_bal} BTC\nETH: {eth_bal} ETH\nTRX: {trx_bal} TRX\nTON: {ton_bal} TON\nUSDT(TRC20): {usdt_bal} USDT"
                found.append(res)
                bot.send_message(message.chat.id, res)
        except Exception:
            continue

    if not found:
        bot.send_message(message.chat.id, "❌ Дар ягон wallet баланс нест.")

bot.polling(
