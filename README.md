# Discord Lua Security Scanner

Bot Discord ini khusus untuk memeriksa file Lua/MonetLoader yang dikirim member.
Bot mendeteksi pola keylogger, pencurian password, pengiriman data ke webhook,
dynamic loader, escape/XOR obfuscation, VM wrapper, LuaJIT FFI, dan akses proses.

Bot tidak lagi memiliki command pembuat script. Satu-satunya slash command adalah:

```text
/setchannelscan
```

Setelah administrator menjalankan command tersebut di sebuah channel, member
cukup mengirim file ke channel itu. Bot akan memindai file `.lua`, `.luac`,
`.luajit`, `.moon`, dan nama ganda seperti `.lua.txt`.

## Environment variables Railway

```env
DISCORD_BOT_TOKEN=...
DISCORD_GUILD_ID=...
OPENAI_API_KEY=...
OPENAI_MODEL=gpt-4o-mini
AI_SCAN_ENABLED=true
MAX_FILE_BYTES=2000000
SCAN_CONFIG_PATH=/data/scan-channels.json
```

`OPENAI_API_KEY` bersifat opsional. Tanpa key, scanner tetap memakai pemeriksaan
lokal. Dengan key, hasil pemeriksaan lokal mendapat lapisan AI triage tambahan.
Kode file diperlakukan sebagai data tidak tepercaya dan tidak pernah dijalankan.

`DISCORD_GUILD_ID` disarankan diisi dengan Server ID agar command muncul cepat.
Bot mengambil Application ID otomatis dari token Discord.

## Pengaturan Discord

Bot membutuhkan scope:

- `bot`
- `applications.commands`

Permission minimal pada server/channel:

- View Channel
- Send Messages
- Read Message History
- Attach Files

Aktifkan **Message Content Intent** pada Discord Developer Portal dan kode
meminta `Guilds`, `Guild Messages`, serta `Message Content` intent agar attachment
dapat dibaca oleh event message.

## Penyimpanan channel

Setting channel disimpan ke `SCAN_CONFIG_PATH`. Railway filesystem biasa dapat
hilang ketika redeploy. Agar setting tetap ada:

1. Buat Railway Volume.
2. Mount volume ke `/data`.
3. Set `SCAN_CONFIG_PATH=/data/scan-channels.json`.

Jika tidak memakai Volume, jalankan `/setchannelscan` lagi setelah restart atau
redeploy.

## Cara penggunaan

1. Administrator masuk ke channel yang ingin dipakai.
2. Jalankan `/setchannelscan`.
3. Member mengirim `contoh.lua`, `contoh.lua.txt`, atau file Lua lain ke channel.
4. Bot membalas hasil scan.

Hasil `BERBAHAYA` atau `RISIKO TINGGI` berarti file tidak boleh dijalankan.
Hasil bersih bukan jaminan mutlak, karena obfuscator baru atau payload native
yang sangat tersamar tetap mungkin membutuhkan analisis manual.

## Catatan keamanan

- Jangan commit `.env`, token Discord, atau API key.
- Jangan jalankan file yang ditandai berbahaya.
- Bot melakukan analisis statis dan tidak mengeksekusi attachment.
- Batas file default adalah 2 MB dan dapat diubah dengan `MAX_FILE_BYTES`.