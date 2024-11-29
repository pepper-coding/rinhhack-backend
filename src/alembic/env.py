# src/alembic/env.py

from __future__ import with_statement
import sys
import os
from logging.config import fileConfig

from sqlalchemy import create_engine, pool
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from alembic import context

# добавьте путь к вашему проекту
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Импортируйте вашу модель Base
from models.user import Base  # замените на правильный путь к вашему Base

# Получаем строку подключения из .env или конфигурации
from dotenv import load_dotenv
import os
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

# Этот объект будет использоваться для создания миграций
target_metadata = Base.metadata

# Конфигурация для Alembic
config = context.config
fileConfig(config.config_file_name)

# Создаем соединение с базой данных
engine = create_engine(DATABASE_URL, poolclass=pool.NullPool)

# Основная функция, которая используется для выполнения миграций
def run_migrations_online():
    connectable = engine.connect()

    with connectable:
        context.configure(
            connection=connectable,
            target_metadata=target_metadata,
            include_schemas=True,
        )

        with context.begin_transaction():
            context.run_migrations()

# Выполнение миграции
run_migrations_online()
