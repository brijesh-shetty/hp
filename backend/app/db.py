"""
db.py — PostgreSQL connection pool for persistent state.
Uses the POSTGRES_URL from config (already set in configmap).
"""
import logging
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from app.config import POSTGRES_URL

logger = logging.getLogger("hpe.db")

_pool = None

def init_pool():
    """Create a connection pool (called once at startup) with retries."""
    global _pool
    if _pool is None:
        import time
        max_retries = 15
        retry_delay = 2
        for attempt in range(1, max_retries + 1):
            try:
                _pool = psycopg2.pool.ThreadedConnectionPool(1, 10, POSTGRES_URL)
                logger.info("PostgreSQL connection pool initialized successfully")
                return
            except Exception as e:
                logger.warning(f"PostgreSQL connection attempt {attempt}/{max_retries} failed: {e}")
                if attempt == max_retries:
                    logger.error("Failed to initialize PostgreSQL connection pool after all retries")
                    raise
                time.sleep(retry_delay)

def get_conn():
    """Get a connection from the pool."""
    if _pool:
        return _pool.getconn()
    raise Exception("Database pool not initialized")

def put_conn(conn):
    """Return a connection to the pool."""
    if _pool and conn:
        _pool.putconn(conn)

def close_pool():
    """Close all connections in the pool."""
    global _pool
    if _pool:
        _pool.closeall()
        _pool = None
        logger.info("PostgreSQL connection pool closed")

def execute_query(query, params=None, fetch=False, fetch_all=False):
    """Helper to execute a query using a connection from the pool."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            conn.commit()
            if fetch:
                if fetch_all:
                    return [dict(row) for row in cur.fetchall()]
                row = cur.fetchone()
                return dict(row) if row else None
            return True
    except Exception as e:
        conn.rollback()
        logger.error(f"Database query failed: {e}\nQuery: {query}\nParams: {params}")
        raise
    finally:
        put_conn(conn)
