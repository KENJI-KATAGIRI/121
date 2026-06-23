# BNI Manager 設計書

## 技術スタック
- Runtime: Python / FastAPI + Uvicorn
- DB: SQLite（sqlite3標準ライブラリ）
- 認証: カスタムトークン認証（Authorizationヘッダー）
- AI: OpenAI GPT-4o
- 外部連携: Stripe, Google Calendar API, Google OAuth2

## ポート・パス
- Port: 8300（127.0.0.1バインド）
- 公開URL: https://gaiaarts.org/bni/（Nginx経由）
- プロセス: nohup uvicorn（systemdなし）
- 再起動コマンド:
  ```bash
  lsof -t -i:8300 | xargs kill -9 2>/dev/null
  sleep 1
  cd /home/ubuntu/apps/bni-app
  nohup .venv/bin/uvicorn main:app --host 127.0.0.1 --port 8300 > /tmp/bni.log 2>&1 &
  sleep 3 && curl -s -o /dev/null -w '%{http_code}' http://localhost:8300/
  ```

## ディレクトリ構成
```
/home/ubuntu/apps/bni-app/
├── main.py            # FastAPIアプリ（全API・全ロジック）
├── .env               # 環境変数
├── .venv/             # Python仮想環境
├── data/
│   └── bni.db         # SQLiteメインDB
└── static/
    └── index.html     # SPAフロントエンド（全機能）
```

## DBスキーマ
- users: id, username, display_name, pw_hash, pw_salt, email, plan, auth_type
- contacts: id, user_id, name, reading, company, category, introduction,
            matching_cache（JSON: recommend/checks/matching）, ...GAINS各フィールド
- one_on_ones: id, user_id, contact_id, transcript, gains_*, follow_up
- memos: id, contact_id, content
- reminders: id, contact_id, remind_date, done
- referrals: id, user_id, contact_id, direction, amount
- google_tokens: user_id, access_token, refresh_token
- sessions: token, user_id, created_at（SQLite永続セッション）
- settings: user_id, key, value

## 認証フロー
- ログイン: POST /api/auth/login → token返却 → localStorage保存
- 検証: AuthMiddleware（全/api/リクエストのAuthorizationヘッダー確認）
- SSO受信: GET /?sso_token= → HMAC検証 → セッション作成
- Google OAuth: /api/auth/google → callback → セッション作成
- ログアウト: POST /api/auth/logout → token削除（メモリ＋DB）

## セッション管理
- メモリキャッシュ: active_sessions dict + session_created dict
- 永続化: sessions テーブル（起動時に_load_sessions()でメモリに復元）
- TTL: 30日（SESSION_TTL = 86400 * 30）
- 保存: _save_session() / 削除: _delete_session()

## セキュリティ実装
- パスワード: pbkdf2（sha256, 260000回, 32バイトsalt）
- Webhook: hmac.compare_digest（定数時間比較）
- IDOR対策: 全SQLに `AND user_id=?` 条件
- SSRF対策: ipaddressモジュールでプライベートIP遮断（extract-contact-url）
- レート制限: _check_auth_rate（15分900秒・5回まで）

## フロントエンド構成（static/index.html）
- SPA（Single Page Application）
- タブ構成: 基本情報/GAINS/紹介文/メモ/リマインダー/マッチング
- API呼び出し: BASE + 'api/...' パターン（絶対パス使用禁止）
- 認証: localStorage の bni_token をAuthorizationヘッダーに付与
- 401発生時: セッション切れオーバーレイ表示（bni_via_sso判定でPWボタン制御）

## AIマッチングキャッシュ
- 保存先: contacts.matching_cache（JSON文字列）
- 構造: { recommend: {categories, saved_at}, checks: [{category, score,...,saved_at}], matching: {matches, saved_at} }
- 保存API: PUT /api/contacts/{cid}/matching-cache
- 起動時読み込み → タブ表示時に即座に復元表示
