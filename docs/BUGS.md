# BNI Manager 既知バグ・未解決事項

## 未解決

### 機能未実装
- [ ] Googleカレンダーのリマインダー同期（OAuth設定済みだが実運用未確認）
- [ ] CSVインポートの文字コード対応（ShiftJIS等）
- [ ] コンタクト削除時の関連レコード（one_on_ones等）整合性確認
- [ ] マルチユーザー運用時の管理者機能（ユーザー管理UI）

### 注意が必要な挙動
- AIマッチングのmatching_cacheはコンタクト情報が更新されても自動再分析されない
  → 大幅な情報更新後は手動で「再分析」が必要
- Google OAuth新規登録はusernames/emailの重複チェックが緩い
  （同一メールで複数登録しようとするとエラー）

## 解決済み（再発注意）

### 文字起こしがBNI Managerに保存されない
- **原因1**: NiceMeetのURL生成に `?system=bni&bu=&bn=` が含まれていなかった
- **原因2**: bu/bnパラメータが空だとGPTがホスト/ゲストを判定できずGAINS抽出失敗
- **対処**: NiceMeet server.js・dashboard.htmlのURL生成を修正済み

### IDOR脆弱性（リマインダー）
- **症状**: 他ユーザーのリマインダーをIDで直接アクセスできた
- **対処**: sync-google-reminder SQLに `AND c.user_id=?` 追加済み

### Webhookタイミング攻撃
- **対処**: `secret != expected` を `not hmac.compare_digest(secret, expected)` に変更済み

### Stripeウェブフック設定なし時のクラッシュ
- **対処**: webhook_secret未設定時に500エラーを返すよう修正済み

### セッション再起動消滅
- **症状**: uvicorn再起動でログインが全て切れる
- **対処**: sessions テーブルに永続化済み（_load_sessions / _save_session）

### 401時の詰まり（SSO/Googleユーザー）
- **症状**: セッション切れ時にパスワードログイン画面が出てSSOユーザーが詰まる
- **対処**: セッション切れオーバーレイ表示、ダッシュボードへ戻るボタン追加
  bni_via_ssoフラグでSSO/Googleユーザーにはパスワードボタンを非表示
