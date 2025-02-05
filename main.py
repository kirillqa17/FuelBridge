import json
import random
import time
import logging
from web3 import Web3
from utils import decryption

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("bridge.log"),  # Логи в файл
        logging.StreamHandler()  # Логи в консоль
    ]
)
logger = logging.getLogger(__name__)

# Загрузка конфигурации
def load_config():
    try:
        with open("config.json", "r") as f:
            config = json.load(f)
        logger.info("Конфигурация загружена")
        return config
    except Exception as e:
        logger.error(f"Ошибка при загрузке конфигурации: {e}")
        exit(1)


# Получение баланса ETH
def get_balance(w3, address):
    try:
        balance = w3.fromWei(w3.eth.get_balance(address), "ether")
        logger.info(f"Баланс кошелька {address}: {balance} ETH")
        return balance
    except Exception as e:
        logger.error(f"Ошибка при получении баланса для {address}: {e}")
        return 0

# Отправка транзакции через Layerswap
def send_transaction(w3, private_key, from_address, to_address, amount_eth):
    try:
        nonce = w3.eth.get_transaction_count(from_address)
        gas_price = w3.eth.gas_price
        tx = {
            "nonce": nonce,
            "to": to_address,
            "value": w3.toWei(amount_eth, "ether"),
            "gas": 21000,
            "gasPrice": gas_price,
            "chainId": 1  # Mainnet
        }
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        logger.info(f"Транзакция отправлена: {tx_hash.hex()}")
        return tx_hash.hex()
    except Exception as e:
        logger.error(f"Ошибка при отправке транзакции: {e}")
        return str(e)

# Основная функция
def main():
    config = load_config()
    evm_keys = decryption.get_wallet_info_from_file()
    # Загрузка кошельков
    try:
        with open("fuel-wallets.txt", "r") as f:
            fuel_addresses = f.read().splitlines()
        logger.info("Кошельки загружены")
    except Exception as e:
        logger.error(f"Ошибка при загрузке кошельков: {e}")
        return

    if len(evm_keys) != len(fuel_addresses):
        logger.error("Количество кошельков EVM и Fuel должно совпадать!")
        return

    # Рандомизация порядка кошельков
    if config["randomize_wallets"]:
        combined = list(zip(evm_keys, fuel_addresses))
        random.shuffle(combined)
        evm_keys, fuel_addresses = zip(*combined)
        logger.info("Порядок кошельков рандомизирован")

    # Подключение к RPC
    w3 = None
    for rpc_url in config["rpc_urls"]:
        try:
            w3 = Web3(Web3.HTTPProvider(rpc_url))
            if w3.isConnected():
                logger.info(f"Подключено к {rpc_url}")
                break
        except Exception as e:
            logger.warning(f"Не удалось подключиться к {rpc_url}: {e}")
    else:
        logger.error("Не удалось подключиться к RPC")
        return

    # Обработка кошельков
    for i, (private_key, fuel_address) in enumerate(zip(evm_keys, fuel_addresses)):
        try:
            # Получение адреса EVM кошелька
            account = w3.eth.account.privateKeyToAccount(private_key)
            from_address = account.address
            logger.info(f"Обработка кошелька {from_address} ({i + 1}/{len(evm_keys)})")

            # Проверка баланса
            balance = get_balance(w3, from_address)
            if balance < config["min_eth"]:
                logger.warning(f"Кошелек {from_address}: недостаточно средств ({balance} ETH)")
                continue

            # Выбор суммы для перевода
            amount_eth = random.uniform(config["min_eth"], config["max_eth"])
            if amount_eth > balance:
                amount_eth = balance
            logger.info(f"Сумма для перевода: {amount_eth} ETH")

            # Отправка транзакции
            tx_hash = send_transaction(w3, private_key, from_address, fuel_address, amount_eth)
            if tx_hash.startswith("0x"):
                logger.info(f"Успешно: {tx_hash}")
            else:
                logger.error(f"Ошибка: {tx_hash}")

            # Задержка
            delay = random.randint(config["min_delay"], config["max_delay"])
            logger.info(f"Ожидание {delay} секунд...")
            time.sleep(delay)

        except Exception as e:
            logger.error(f"Ошибка при обработке кошелька {from_address}: {e}")

if __name__ == "__main__":
    main()