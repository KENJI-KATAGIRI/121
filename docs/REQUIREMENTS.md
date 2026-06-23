# BNI Manager 要件定義

## サービス概要
BNIメンバー向けCRM・1対1ミーティング管理システム
URL: https://gaiaarts.org/bni/
連携: NiceMeet（SSO・文字起こし自動保存）

## 主要機能

### コンタクト管理
- メンバー情報登録（GAINS情報・紹介文・カテゴリ等）
- URL（Web名刺等）からの情報自動抽出（SSRF対策済み）
- CSVインポート・エクスポート（ZIPダウンロード）
- 紹介文AI自動生成（GPT-4o）

### 1対1ミーティング（one_on_ones）
- NiceMeetの文字起こしから自動登録
- GAINS情報自動抽出・保存
- 手動での面談記録追加

### AIマッチング
- おすすめ紹介カテゴリ分析（GPT-4o）
- カテゴリ相性チェック（スコア100点・履歴保存）
- 登録コンタクト間のマッチング分析
- 結果はcontacts.matching_cacheに自動保存・永続表示

### リマインダー・メモ
- コンタクトごとのメモ
- 日付指定リマインダー
- Googleカレンダー連携

### 認証
- パスワード認証（pbkdf2）
- Google OAuth SSO（NiceMeetダッシュボード経由）
- NiceMeet SSO（HMAC署名トークン）
- セッション: SQLite永続化（30日TTL）

### 決済
- Stripeサブスク（無料/有料プラン）
- UTAGEウェブフック連携

## ターゲット
- BNIメンバー（主に片桐さんのチャプター）
- 将来的にマルチユーザーSaaS展開
