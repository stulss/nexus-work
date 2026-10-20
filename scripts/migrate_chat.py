"""이미 만들어진 DB 에 AI 채팅방(대화방)과 AI 제한 열을 더한다. root 계정으로 접속한다. 여러 번 실행해도 안전하다.

사용: python scripts/migrate_chat.py [--db nexus] [--db nexus_test]   (기본: 둘 다)
- chat_conversations 표를 만들고, chat_messages 에 conversation_id 열을 더한다.
- 예전 대화(conversation_id 없음)는 사용자마다 '이전 대화' 한 개로 묶어 그대로 보이게 한다. 지우거나 바꾸는 기록은 없다.
- users.ai_restricted 열(AI Tool 제한, 기본 0)을 더한다.
- nexus_app 에 chat_conversations 권한을 준다(db/grants.sql 과 같은 내용).
- 새로 DB 를 만들 때는 db/schema.sql·grants.sql 이 이미 이 내용을 포함하므로 이 스크립트가 필요 없다."""
import argparse
import os
import re
import sys
from pathlib import Path

import pymysql
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def has_column(cur, db, table, column):
    cur.execute("SELECT 1 FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND column_name=%s",
                (db, table, column))
    return bool(cur.fetchone())


def has_table(cur, db, table):
    cur.execute("SELECT 1 FROM information_schema.tables WHERE table_schema=%s AND table_name=%s", (db, table))
    return bool(cur.fetchone())


def conversations_ddl():
    schema = (ROOT / "db" / "schema.sql").read_text(encoding="utf-8")
    return re.search(r"CREATE TABLE chat_conversations \(.*?\) ENGINE=InnoDB;", schema, re.S).group(0).removesuffix(";")


def migrate(db):
    con = pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ.get("DB_PORT", "3307")), user="root",
                          password=os.environ["MYSQL_ROOT_PASSWORD"], database=db, autocommit=True, charset="utf8mb4")
    cur = con.cursor()
    done = []
    if not has_table(cur, db, "chat_conversations"):
        cur.execute(conversations_ddl())
        done.append("+table chat_conversations")
    if not has_column(cur, db, "chat_messages", "conversation_id"):
        cur.execute("ALTER TABLE chat_messages ADD COLUMN conversation_id INT UNSIGNED NULL AFTER user_id, "
                    "ADD KEY idx_chat_conv (conversation_id, id), "
                    "ADD CONSTRAINT fk_chat_conv FOREIGN KEY (conversation_id) REFERENCES chat_conversations(id)")
        done.append("+column chat_messages.conversation_id")
    if not has_column(cur, db, "users", "ai_restricted"):
        cur.execute("ALTER TABLE users ADD COLUMN ai_restricted TINYINT(1) NOT NULL DEFAULT 0 AFTER pinned")
        done.append("+column users.ai_restricted")
    # 예전 대화 묶기: 대화방이 없는 기록이 있는 사용자마다 '이전 대화' 한 개
    cur.execute("SELECT DISTINCT user_id FROM chat_messages WHERE conversation_id IS NULL")
    for (user_id,) in cur.fetchall():
        cur.execute("INSERT INTO chat_conversations(user_id, title, created_at, updated_at) "
                    "SELECT %s, '이전 대화', MIN(created_at), MAX(created_at) FROM chat_messages "
                    "WHERE user_id=%s AND conversation_id IS NULL", (user_id, user_id))
        cur.execute("UPDATE chat_messages SET conversation_id=%s WHERE user_id=%s AND conversation_id IS NULL",
                    (cur.lastrowid, user_id))
        done.append(f"user {user_id}: old messages grouped")
    cur.execute(f"GRANT SELECT, INSERT ON `{db}`.chat_conversations TO 'nexus_app'@'%'")
    cur.execute(f"GRANT UPDATE (title, updated_at) ON `{db}`.chat_conversations TO 'nexus_app'@'%'")
    con.close()
    print(db, "->", done or "already up to date")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", action="append", choices=("nexus", "nexus_test"))
    args = ap.parse_args()
    for db in args.db or ["nexus", "nexus_test"]:
        migrate(db)


if __name__ == "__main__":
    sys.exit(main())
