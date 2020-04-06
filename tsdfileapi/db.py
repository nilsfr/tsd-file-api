
"""sqlite db backend designed for JSON data."""

# pylint: disable=missing-docstring

import datetime
import logging
import re
import json
import sqlite3

from abc import ABC, abstractmethod
from contextlib import contextmanager

import psycopg2
import psycopg2.pool

from sqlalchemy.pool import QueuePool
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError, IntegrityError, StatementError

# pylint: disable=relative-import
from tsdfileapi.squril import SqliteQueryGenerator, PostgresQueryGenerator
from tsdfileapi.utils import check_filename, IllegalFilenameException


def sqlite_init(path, name='api-data.db', builtin=False):
    dbname = name
    if not builtin:
        dburl = 'sqlite:///' + path + '/' + dbname
        engine = create_engine(dburl, poolclass=QueuePool)
    else:
        engine = sqlite3.connect(path + '/' + dbname)
    return engine


def postgres_init(dbconfig):
    min_conn = 5
    max_conn = 15
    dsn = f"dbname={dbconfig['dbname']} user={dbconfig['user']} password={dbconfig['pw']} host={dbconfig['host']}"
    pool = psycopg2.pool.SimpleConnectionPool(
        min_conn, max_conn, dsn
    )
    return pool


@contextmanager
def session_scope(engine):
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
        session.commit()
    except (OperationalError, IntegrityError, StatementError) as e:
        session.rollback()
        raise e
    finally:
        session.close()


@contextmanager
def sqlite_session(engine):
    session = engine.cursor()
    try:
        yield session
        session.close()
    except Exception as e:
        session.close()
        engine.rollback()
        raise e
    finally:
        session.close()
        engine.commit()


@contextmanager
def postgres_session(pool):
    engine = pool.getconn()
    session = engine.cursor()
    try:
        yield session
        session.close()
    except Exception as e:
        session.close()
        engine.rollback()
        raise e
    finally:
        session.close()
        engine.commit()
        pool.putconn(engine)


class DatabaseBackend(ABC):

    def __init__(self, engine, verbose=False, requestor=None):
        super(DatabaseBackend, self).__init__()
        self.engine = engine
        self.verbose = verbose
        self.requestor = requestor

    @abstractmethod
    def initialise(self):
        pass

    @abstractmethod
    def tables_list(self):
        pass

    @abstractmethod
    def table_insert(self, table_name, data):
        pass

    @abstractmethod
    def table_update(self, table_name, uri, data):
        pass

    @abstractmethod
    def table_delete(self, table_name, uri):
        pass

    @abstractmethod
    def table_select(self, table_name, uri):
        pass


class SqliteBackend(DatabaseBackend):

    """
    This backend works reliably, and offers decent read-write
    performance to API clients under the following conditions:

    a) using network storage, like NFS

        - using rollback-mode for transactions
        - where clients do not perform long-running read operations

    b) not using network storage

        - using WAL-mode for transactions
        - clients can perform long-running reads without
          blocking writers

    Briefly, WAL-mode (which offer non-blocking read/write) cannot
    be reliably used over NFS, because the locking primitives
    used by SQLite to prevent DB corruption are not implemented. So
    if you are using NFS, you must use rollback-mode. This however,
    means that writers require exclusive locks to write, which means
    that long-running reads by clients would block writers. This
    may be unfortunate, depending on the use case.

    For more background refer to:

        - https://www.sqlite.org/lockingv3.html
        - https://www.sqlite.org/wal.html
        - https://www.sqlite.org/threadsafe.html

    """

    generator_class = SqliteQueryGenerator

    def __init__(self, engine, verbose=False, schema=None, requestor=None):
        self.engine = engine
        self.verbose = verbose
        self.table_definition = '(data json unique not null)'
        self.requestor = requestor

    def initialise(self):
        pass

    def tables_list(self):
        query = "select name FROM sqlite_master where type = 'table'"
        with sqlite_session(self.engine) as session:
            res = session.execute(query).fetchall()
        if not res:
            return []
        else:
            out = []
            for row in res:
                name = row[0]
                if not name.endswith('_metadata') and not name.endswith('_audit'):
                    out.append(row[0])
            return out

    def table_insert(self, table_name, data):
        try:
            dtype = type(data)
            insert_stmt = f'insert into "{table_name}" (data) values (?)'
            target = []
            if dtype is list:
                for element in data:
                    target.append((json.dumps(element),))
            elif dtype is dict:
                target.append((json.dumps(data),))
            try:
                with sqlite_session(self.engine) as session:
                    session.executemany(insert_stmt, target)
                return True
            except (sqlite3.ProgrammingError, sqlite3.OperationalError) as e:
                with sqlite_session(self.engine) as session:
                    session.execute(f'create table if not exists "{table_name}" {self.table_definition}')
                    session.executemany(insert_stmt, target)
                return True
        except sqlite3.ProgrammingError as e:
            logging.error('Syntax error?')
            raise e
        except sqlite3.IntegrityError as e:
            logging.error('Duplicate row')
            raise e
        except sqlite3.OperationalError as e:
            logging.error('Database issue')
            raise e
        except Exception as e:
            logging.error('Not sure what went wrong')
            raise e

    def table_update(self, table_name, uri_query, data):
        old = list(self.table_select(table_name, uri_query))
        sql = self.generator_class(f'"{table_name}"', uri_query, data=data)
        with sqlite_session(self.engine) as session:
            session.execute(sql.update_query)
        audit_data = []
        for val in old:
            audit_data.append({
                'timestamp': datetime.datetime.now().isoformat(),
                'diff': data,
                'previous': json.loads(val),
                'identity': self.requestor
            })
        self.table_insert(f'{table_name}_audit', audit_data)
        return True

    def table_delete(self, table_name, uri_query):
        sql = self.generator_class(f'"{table_name}"', uri_query)
        with sqlite_session(self.engine) as session:
            session.execute(sql.delete_query)
        return True

    def table_select(self, table_name, uri_query):
        sql = self.generator_class(f'"{table_name}"', uri_query)
        with sqlite_session(self.engine) as session:
            for row in session.execute(sql.select_query):
                yield row[0]


class PostgresBackend(object):

    """
    A PostgreSQL backend. PostgreSQL is a full-fledged
    client-server relational DB, implementing MVCC for
    concurrency control. This backend is therfore
    suitable for applications that have many simultaneous
    read and write operations, with full ACID compliance
    and no reader-writer blocking.

    For more info on MVCC, see:
    https://www.postgresql.org/docs/12/mvcc-intro.html

    """

    generator_class = PostgresQueryGenerator

    def __init__(self, pool, verbose=False, schema=None, requestor=None):
        self.pool = pool
        self.verbose = verbose
        self.table_definition = '(data jsonb not null, uniq text unique not null)'
        self.schema = schema if schema else 'public'
        self.requestor = requestor

    def initialise(self):
        with postgres_session(self.pool) as session:
            for stmt in self.generator_class.db_init_sql:
                    session.execute(stmt)
        return True

    def tables_list(self):
        query = f"""select table_name from information_schema.tables
            where table_schema = '{self.schema}'"""
        with postgres_session(self.pool) as session:
            session.execute(query)
            res = session.fetchall()
        if not res:
            return []
        else:
            out = []
            for row in res:
                name = row[0]
                if not name.endswith('_metadata') and not name.endswith('_audit'):
                    out.append(row[0])
            return out

    def table_insert(self, table_name, data):
        try:
            dtype = type(data)
            insert_stmt = f'insert into {self.schema}."{table_name}" (data) values (%s)'
            target = []
            if dtype is list:
                for element in data:
                    target.append((json.dumps(element),))
            elif dtype is dict:
                target.append((json.dumps(data),))
            try:
                with postgres_session(self.pool) as session:
                    session.executemany(insert_stmt, target)
                return True
            except (psycopg2.ProgrammingError, psycopg2.OperationalError) as e:
                table_create = f'create table if not exists {self.schema}."{table_name}"{self.table_definition}'
                trigger_create = f"""
                    create trigger ensure_unique_data before insert on {self.schema}."{table_name}"
                    for each row execute procedure unique_data()"""
                with postgres_session(self.pool) as session:
                    session.execute(f'create schema if not exists {self.schema}')
                    session.execute(table_create)
                    session.execute(trigger_create)
                    session.executemany(insert_stmt, target)
                return True
        except psycopg2.ProgrammingError as e:
            logging.error('Syntax error?')
            raise e
        except psycopg2.IntegrityError as e:
            logging.error('Duplicate row')
            raise e
        except psycopg2.OperationalError as e:
            logging.error('Database issue')
            raise e
        except Exception as e:
            logging.error('Not sure what went wrong')
            raise e

    def table_update(self, table_name, uri_query, data):
        old = list(self.table_select(table_name, uri_query))
        sql = self.generator_class(f'{self.schema}."{table_name}"', uri_query, data=data)
        with postgres_session(self.pool) as session:
            session.execute(sql.update_query)
        audit_data = []
        for val in old:
            audit_data.append({
                'timestamp': datetime.datetime.now().isoformat(),
                'diff': data,
                'previous': val,
                'identity': self.requestor
            })
        self.table_insert(f'{table_name}_audit', audit_data)
        return True

    def table_delete(self, table_name, uri_query):
        sql = self.generator_class(f'{self.schema}."{table_name}"', uri_query)
        with postgres_session(self.pool) as session:
            session.execute(sql.delete_query)
        return True

    def table_select(self, table_name, uri_query):
        sql = self.generator_class(f'{self.schema}."{table_name}"', uri_query)
        with postgres_session(self.pool) as session:
            session.execute(sql.select_query)
            for row in session:
                yield row[0]
