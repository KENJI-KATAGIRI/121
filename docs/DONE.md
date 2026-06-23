# BNI Manager 完了済み機能（再実装・破壊禁止）

## コンタクト管理
- [x] GAINS情報フィールド（goals/accomplishments/interests/networks/skills）
- [x] URL自動抽出（SSRF対策: プライベートIP遮断・httpx使用）
- [x] 紹介文AI生成（GPT-4o）+ 保存ボタン（ローディング・成功フィードバック付き）
- [x] CSVインポート（ファイル・URL）
- [x] ZIPエクスポート

## AIマッチング（contacts.matching_cacheに自動保存）
- [x] おすすめ紹介カテゴリ（priority: high/medium/low）
- [x] カテゴリ相性チェック（score/verdict/reasons/concerns/scenario、履歴蓄積）
- [x] 登録コンタクトマッチング（スコア順・理由・紹介機会）
- [x] タブ再表示時に保存済み結果を即表示（生成日時付き）

## 1対1ミーティング
- [x] NiceMeet文字起こしからの自動登録（Webhookで受信）
- [x] GAINS自動抽出・保存
- [x] 手動追加・編集

## 認証・セキュリティ（変更注意）
- [x] pbkdf2パスワードハッシュ（sha256, 260000回）
- [x] セッションSQLite永続化（sessions table、30日TTL）
- [x] NiceMeet SSO（HMAC署名トークン受信・検証）
- [x] Google OAuth SSO
- [x] AuthMiddleware（全APIリクエスト検証）
- [x] IDOR対策（全SQL `AND user_id=?`）
- [x] SSRF対策（ipaddressモジュール）
- [x] Webhook定数時間比較（hmac.compare_digest）
- [x] レート制限（認証15分5回）

## UX
- [x] 401時セッション切れオーバーレイ（ダッシュボード誘導）
- [x] bni_via_ssoフラグによるPWボタン制御
- [x] 紹介文保存ボタンのフィードバック（保存中…→✓保存しました）

## Stripe・決済
- [x] Stripeサブスク（checkout/portal）
- [x] UTAGEウェブフック受信・プラン更新
- [x] Stripe顧客ID不整合時のauto-clear
