# -*- coding: utf-8 -*-
"""集中配置。

所有敏感信息（数据库口令、JWT 密钥、部署者私钥）只从环境变量 / .env 读取，
严禁硬编码进代码或提交进仓库。

使用方式：复制 backend/.env.example 为 backend/.env，按需填写后启动。
"""
import os

from dotenv import load_dotenv

# 显式按 backend 目录加载 .env，避免受启动工作目录影响
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))


class Config:
    # ---- 数据库（SQL Server）----
    DB_SERVER = os.getenv('DB_SERVER', 'localhost')
    DB_NAME = os.getenv('DB_NAME', 'ZKVotingSystem')
    DB_USER = os.getenv('DB_USER', 'sa')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')  # 仅来自环境变量，无默认值
    DB_PORT = int(os.getenv('DB_PORT', 1433))
    DB_DRIVER = os.getenv('DB_DRIVER', 'ODBC Driver 17 for SQL Server')

    # SQLAlchemy 连接字符串
    SQLALCHEMY_DATABASE_URI = (
        f"mssql+pyodbc://{DB_USER}:{DB_PASSWORD}@{DB_SERVER}:{DB_PORT}/{DB_NAME}"
        f"?driver={DB_DRIVER}&TrustServerCertificate=yes"
    )

    # ---- JWT ----
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', '')  # 仅来自环境变量，无默认值
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 86400))

    # ---- 服务 ----
    HOST = os.getenv('HOST', '127.0.0.1')
    PORT = int(os.getenv('PORT', 5000))

    # ---- CORS ----
    CORS_ORIGINS = os.getenv(
        'CORS_ORIGINS', 'http://127.0.0.1:3001,http://localhost:3001'
    ).split(',')

    # ---- 区块链（services/blockchain.py 直接读取同名环境变量）----
    # Windows 下 localhost 会先解析到 IPv6(::1)，而 Hardhat 只监听 IPv4，
    # 每次连接要空等约 2s 才回退到 IPv4；因此默认值用 127.0.0.1。
    BLOCKCHAIN_RPC_URL = os.getenv('BLOCKCHAIN_RPC_URL', 'http://127.0.0.1:8545')
    CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS', '')
    DEPLOYER_PRIVATE_KEY = os.getenv('DEPLOYER_PRIVATE_KEY', '')  # 严禁写入代码/仓库
    CHAIN_ID = int(os.getenv('CHAIN_ID', 31337))

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    def __init__(self):
        # 启动自检：缺失必填配置时尽早、清晰地失败，而不是带着弱默认值裸奔
        missing = [
            name for name in ('DB_PASSWORD', 'JWT_SECRET_KEY')
            if not getattr(self, name)
        ]
        if missing:
            raise RuntimeError(
                '缺少必填配置: ' + ', '.join(missing)
                + '。请复制 backend/.env.example 为 backend/.env 并填写后重试。'
            )


config = Config()
