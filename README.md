# 概要
セキュリティ知識強化の一環として、段階的に機能を拡張していくPythonを使用した簡易的な自作EDRの記録です。徐々に機能を増やして実用的にしていくことを目標にしています。

## 実装した機能（随時更新中）
- ファイルの更新日時（mtime）に加えて、SHA-256ハッシュ値を比較して変更を検知。
- `config.json`で設定を一元化し、複数ファイルを同時監視。
- Windowsイベントログからファイルを変更したユーザー、実行ファイルパス、プロセスID、編集されたファイルパスを特定。
- ファイル削除した場合に、WindowsイベントログのハンドルIDから削除したプロセスとユーザーを特定。
- PythonでWindowsイベントログを検索しているため、自分自身の処理をスキップしてFalse Positiveを低減。
- OSのログ書き込み遅延を考慮し、複数回試行して取りこぼしを防止。
- ファイルのハッシュ計算のメモリクラッシュを考慮。
- 二重検知を防ぐためにハンドルIDを保持（最新100件）

## 攻撃側スクリプト
- 0.1秒ごとにSecurity Logを削除。

## 注意点
※OS監査ポリシーの有効化と対象ファイルのSACLが必要。

## 免責事項
本リポジトリに掲載されている情報は、情報セキュリティの教育および学習、並びに正当な防御手法の向上を目的としています。
掲載された手法を許可されていない対象に対して実行することは違法であり、刑事罰の対象となる可能性があります。本リポジトリの内容を悪用したことにより生じたいかなる損害についても、製作者は一切の責任を負いません。
攻撃手法の理解は、より強固なセキュリティを構築するための第一歩であることを忘れないでください。

## Disclaimer
This repository is for educational and ethical security testing purposes only.
Usage of the tools or techniques provided in this repository for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws.
The author assumes no liability and is not responsible for any misuse or damage caused by this information.
