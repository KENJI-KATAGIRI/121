# BNI Manager — Claude作業ガイド

## 必ず最初に読むこと
- docs/REQUIREMENTS.md — 何を作るか
- docs/DESIGN.md       — 構造・DB・API設計
- docs/BUGS.md         — 既知バグ（再発させるな）
- docs/DONE.md         — 完了済み（再実装・破壊するな）

## 基本情報
- Port: 8300（127.0.0.1バインド）
- URL: https://gaiaarts.org/bni/
- メインファイル: main.py（FastAPI）
- フロント: static/index.html（SPA）
- DB: data/bni.db（SQLite）
- Python仮想環境: .venv/

## よく使うコマンド
```bash
# 再起動
lsof -t -i:8300 | xargs kill -9 2>/dev/null
sleep 1
nohup .venv/bin/uvicorn main:app --host 127.0.0.1 --port 8300 > /tmp/bni.log 2>&1 &
sleep 3 && curl -s -o /dev/null -w '%{http_code}' http://localhost:8300/

# ログ確認
tail -f /tmp/bni.log

# 構文チェック
.venv/bin/python -c 'import main; print("OK")'

# DB確認
sqlite3 data/bni.db '.tables'
```

## 作業ルール
1. 変更前に必ずバックアップ: `cp main.py main.py.bak_$(date +%Y%m%d)`
2. Pythonコードをssh heredocで書く場合はブラケットに注意（`cat > /tmp/patch.py` 経由で）
3. 変更後は `.venv/bin/python -c 'import main; print("OK")'` で構文確認
4. 再起動後に `curl -s -o /dev/null -w '%{http_code}' http://localhost:8300/` で200確認
5. 完了したらgit commit & push（VPS上で実行）

## 重要な実装メモ
- フロントのAPI呼び出しは `BASE + 'api/...'` パターン（絶対パス禁止）
- 全APIはAuthMiddlewareが認証確認（open_pathsリストに明示した場合のみ除外）
- セッション: active_sessions dict（メモリ）+ sessions table（DB永続）の二層構造
- マイグレーション: init_db()の末尾にALTER TABLE追加（try/exceptで囲む）
- SSO受信URLは `/?sso_token=` でstaticファイルとして処理される点に注意
