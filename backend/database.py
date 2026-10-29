# -*- coding: utf-8 -*-
import pyodbc
from contextlib import contextmanager
from config import config
import logging

logger = logging.getLogger(__name__)

class Database:
    def __init__(self):
        self.connection_string = self._get_connection_string()

    def _get_connection_string(self):
        return (
            f"DRIVER={{{config.DB_DRIVER}}};"
            f"SERVER={config.DB_SERVER},{config.DB_PORT};"
            f"DATABASE={config.DB_NAME};"
            f"UID={config.DB_USER};"
            f"PWD={config.DB_PASSWORD};"
            "TrustServerCertificate=yes;"
        )

    @contextmanager
    def get_connection(self):
        connection = None
        try:
            connection = pyodbc.connect(self.connection_string)
            yield connection
        except pyodbc.Error as e:
            logger.error(f"数据库连接错误: {e}")
            raise
        finally:
            if connection:
                connection.close()

    def execute_query(self, query, params=None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)

                # 对于 SELECT 查询
                if query.strip().upper().startswith('SELECT'):
                    try:
                        columns = [column[0] for column in cursor.description]
                        results = []
                        for row in cursor.fetchall():
                            results.append(dict(zip(columns, row)))
                        return results
                    except Exception as e:
                        logger.error(f"获取查询结果错误: {e}")
                        return []

                # 对于 INSERT 查询
                elif query.strip().upper().startswith('INSERT'):
                    conn.commit()
                    # 获取最后插入的ID
                    cursor.execute("SELECT @@IDENTITY AS id")
                    result = cursor.fetchone()
                    return result[0] if result else True

                # 对于其他查询
                else:
                    conn.commit()
                    return cursor.rowcount

            except pyodbc.Error as e:
                conn.rollback()
                logger.error(f"查询执行错误: {e}")
                raise

# 创建全局数据库实例
db = Database()