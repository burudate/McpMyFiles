# mcp-myfiles

ローカル（Windows）で自動生成されたファイル、特にテンポラリ領域のファイルについて、
**いつ・だれが・なぜ** 作ったのかを調べるための MCP サーバ。すべてのツールは読み取り専用。

作成元を厳密に確定するのではなく、ファイル名・配置場所・中身・署名・時刻の一致などの手がかりと、
Web 検索（MCP クライアント側で実行）を組み合わせて推測する、という方針です。

## ツール一覧

| ツール | 分かること | 管理者権限 |
|---|---|---|
| `list_temp_directories` | %TEMP%、`C:\Windows\Temp`、`SystemTemp` などの一覧と、読み取れるかどうか | 不要 |
| `find_recent_files` | 直近 N 分に作成（または更新）されたファイル。ファイル名から作成元を推定した結果付き | 不要 |
| `summarize_temp_activity` | Temp 直下のエントリごとの件数・容量・作成時刻の範囲（どのアプリが大量に作っているか） | 不要 |
| `inspect_file` | 作成・更新・アクセス日時、属性、**所有者**、**Zone.Identifier（ダウンロード元 URL）**、ファイル種別、発行元と署名、SHA-256、同じ時刻の前後に作られた兄弟ファイル。フォルダの場合は中身と、中にある exe の製品名や署名。さらに **Web 検索用のキーワード候補** | 不要 |
| `preview_file` | 先頭部分のテキスト表示、16 進ダンプ、またはバイナリ内の文字列抽出（埋め込まれたパスや URL など） | 不要 |
| `search_usn_journal` | NTFS の変更ジャーナルに残った作成・削除の履歴（**削除済みファイルも含む**）。直近数日ぶん | 不要（削除済みファイルの名前まで見るには必要） |
| `find_processes_using_file` | **今そのファイルを開いているプロセス**（Restart Manager API を使用） | 不要 |
| `find_processes_started_near` | ファイルの作成時刻の前後に起動し、今も動いているプロセス（作成元の候補） | 不要 |
| `get_process_info` | プロセスのコマンドライン、ユーザー、カレントディレクトリ、親プロセスのチェーン、子プロセス | 不要 |
| `search_file_events` | Sysmon や Security のイベントログに残った作成・削除の記録（Sysmon を導入している場合のみ） | 通常は必要 |

## セットアップ

```powershell
cd C:\Users\festi\Documents\OtherProjects\Claude\mcp-myfiles
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

### Claude Code に登録

```powershell
claude mcp add myfiles --scope user -- C:\Users\festi\Documents\OtherProjects\Claude\mcp-myfiles\.venv\Scripts\python.exe -m myfiles_mcp
```

### Claude Desktop に登録（`claude_desktop_config.json`）

```json
{
  "mcpServers": {
    "myfiles": {
      "command": "C:\\Users\\festi\\Documents\\OtherProjects\\Claude\\mcp-myfiles\\.venv\\Scripts\\python.exe",
      "args": ["-m", "myfiles_mcp"]
    }
  }
}
```

`C:\Windows\Temp` や `SystemTemp` の中を見たいときは、クライアントを管理者として実行してください。

## 別の PC に入れる手順

### 事前に必要なもの（新しい PC）

- **Windows 10（2017 年秋の更新以降）または Windows 11**
- **Python 3.12 以上**：<https://www.python.org/downloads/> からインストールします。
  インストーラーで **「py launcher」にチェックが入っていること** を確認してください（標準で入っています）。
- **Claude Code**（VS Code 拡張または CLI）か **Claude Desktop**
- インターネット接続（手順 3 で部品をダウンロードするため）

### 手順 1：元の PC で zip を作る

`.venv`（PC ごとに作り直すもの）、`__pycache__`、`*.egg-info` を除いた次のファイルを zip にまとめます。

```
mcp-myfiles/
├─ myfiles_mcp/   （プログラム本体）
├─ pyproject.toml
└─ README.md
```

できた zip を、USB メモリや OneDrive などで新しい PC にコピーします。

### 手順 2：展開する

例として `C:\tools` に展開すると、`C:\tools\mcp-myfiles` ができます。
**この後はフォルダを移動しないでください**。移動した場合は手順 3 からやり直してください。

### 手順 3：インストール（PowerShell で実行）

```powershell
cd C:\tools\mcp-myfiles
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

最後に `Successfully installed ...` と表示されれば成功です。

### 手順 4：Claude に登録

**Claude Code の場合**

```powershell
claude mcp add myfiles --scope user -- C:\tools\mcp-myfiles\.venv\Scripts\python.exe -m myfiles_mcp
```

`claude` が見つからないと言われた場合は、VS Code 拡張に同梱されている CLI を使います。

```powershell
$claude = (Get-ChildItem "$env:USERPROFILE\.vscode\extensions\anthropic.claude-code-*\resources\native-binary\claude.exe" | Select-Object -Last 1).FullName
& $claude mcp add myfiles --scope user -- C:\tools\mcp-myfiles\.venv\Scripts\python.exe -m myfiles_mcp
```

**Claude Desktop の場合**

`%APPDATA%\Claude\claude_desktop_config.json` に次の内容を追加し、Claude Desktop を完全に終了してから起動し直します。
JSON の中では `\` を `\\` と 2 つ重ねて書きます。

```json
{
  "mcpServers": {
    "myfiles": {
      "command": "C:\\tools\\mcp-myfiles\\.venv\\Scripts\\python.exe",
      "args": ["-m", "myfiles_mcp"]
    }
  }
}
```

### 手順 5：動作確認

- Claude Code では、`claude mcp get myfiles`（手順 4 で `$claude` を使った場合は `& $claude mcp get myfiles`）を実行し、**`Connected`** と表示されれば成功です。
- 新しい会話で「Temp フォルダの一覧を出して」と頼み、`list_temp_directories` ツールが使われれば OK です。

### うまくいかないとき

| 症状 | 対処 |
|---|---|
| `py` が見つからない | Python を入れ直し、「py launcher」にチェックを入れる |
| `pip install` でエラーになる | Python が 3.12 より古い可能性があります。`py -3 --version` で確認してください |
| `Connected` にならない | `C:\tools\mcp-myfiles\.venv\Scripts\python.exe -m myfiles_mcp` を直接実行し、エラーが出ないか見る（何も表示されずに待機すれば正常なので Ctrl+C で終了） |
| `C:\Windows\Temp` の中が見られない | VS Code や Claude Desktop を「管理者として実行」する |

### 補足

- ユーザー名や Temp フォルダの場所は PC ごとに自動で判別するので、プログラム側の設定変更は不要です。
- 元の PC でプログラムを更新したら、`myfiles_mcp` フォルダを新しい PC に上書きコピーするだけで反映されます（`.venv` はそのままで OK）。
  ただし `pyproject.toml` の依存パッケージを変えた場合は、手順 3 の `pip install -e .` をもう一度実行してください。

## 調査の流れ（例）

1. `summarize_temp_activity`：どこに大量のファイルが作られているかを見る
2. `find_recent_files`：対象を絞る
3. `inspect_file`：所有者、署名、ダウンロード元、中の exe、兄弟ファイルを見る
4. `inspect_file` が返した `web_search_queries` で Web 検索し、正体を推測する
5. 必要に応じて以下で裏付けをとる
   - `search_usn_journal`：どのくらいの頻度で作られ、消されているか
   - `find_processes_started_near`：作成時刻に動いていたプロセス
   - スケジュールタスクの実行時刻との照合
6. `preview_file`：中身から「なぜ」作られたかを推測する（ログのヘッダ、埋め込みパスなど）

## 制限事項

- ファイル名による作成元の推定（`heuristics.py`）はあくまでヒントです。
- Windows は「どのプロセスがファイルを作ったか」を記録しないため、作成元は推測になります。
  確定したい場合は Sysmon（Microsoft Sysinternals）を導入すると、`search_file_events` で調べられるようになります。
- 走査は 1 回あたり最大 300,000 エントリまで（`MAX_SCAN_ENTRIES`）です。
- SHA-256 は 200MB 以下のファイルだけ計算します。
