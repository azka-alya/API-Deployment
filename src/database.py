from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base

# SQLALCHEMY_DATABASE_URL = "sqlite:///./tuciwir.db"
# SQLALCHEMY_DATABASE_URL = "postgres://olavibuzyktcds:2e2d9fbe8917a0e81364d393a56ffef96c1a361b937817c1d544d911b26550dc@ec2-3-230-149-158.compute-1.amazonaws.com:5432/dbfkobcp28ff3h"
SQLALCHEMY_DATABASE_URL = "postgresql://tuciwir@tuciwir-sql:Password123@tuciwir-sql.postgres.database.azure.com:5432/tuciwir"


def init_connection_engine():
    db_config = {
        "pool_size": 5,
        "max_overflow": 2,
        "pool_timeout": 30,
        "pool_recycle": 1800
    }
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, **db_config
    )
    return engine

db = init_connection_engine()

Base = declarative_base()
