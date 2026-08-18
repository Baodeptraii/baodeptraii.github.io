---
title: "Tuần 2 — System Foundation"
date: 2026-08-18 10:00:00 +0700
categories: [system]
tags: [windows, linux, event-log, process, ssh, persistence, mitre-attck]
---

Tiếp nối tuần trước, tuần này mình đào sâu vào nền tảng **hệ thống**: Windows Event Log, process/process tree, file system, log trên Linux, SSH, và một mảng rất hay bị bỏ qua nhưng cực kỳ quan trọng với dân DFIR/SOC — **persistence**, tức là cách attacker "bám trụ" lại trên máy sau khi đã xâm nhập. Cuối bài là 4 lab thực hành, trong đó có phần mình dựng luôn kịch bản brute-force SSH và tạo persistence giả lập để soi log từ đầu đến cuối.

## 1. Windows Event Log

**File log** (tệp nhật ký) là một tệp tin chứa các bản ghi về các sự kiện xảy ra trong một hệ thống hoặc ứng dụng. Mỗi bản ghi thường bao gồm thông tin về thời gian, nguồn gốc, loại sự kiện và các chi tiết liên quan.

**Windows Event Logs** gồm những event liên quan đến phần mềm/phần cứng, OS, bảo mật. Service Windows Event Log chịu trách nhiệm quản lý các event, thu thập từ nhiều nguồn khác nhau và lưu trữ tập trung tại một thư mục.

### 5 log type

- **System log**: các event liên quan đến hệ thống và các thành phần của nó, chẳng hạn lỗi dịch vụ không thể khởi động trong quá trình boot.
- **Application log**: sự kiện sinh ra bởi ứng dụng, ví dụ lỗi khi khởi động ứng dụng.
- **Security log**: các sự kiện liên quan đến an toàn hệ thống — đăng nhập thành công/thất bại, xóa tệp...
- **Setup log**: các sự kiện xảy ra trong quá trình cài đặt hệ điều hành Windows.
- **Forwarded log**: các event log được chuyển tiếp từ máy tính khác trong cùng mạng.

### Các thành phần chính của một nhật ký sự kiện

- **Log Key**: khóa `Eventlog` chứa nhiều nhật ký/khóa con (subkey), dùng để định vị tài nguyên liên quan.
- **Event Categories**: phân nhóm sự kiện theo danh mục, giúp Event Viewer tìm kiếm dễ hơn.
- **Event Sources**: chính là chương trình tạo ra sự kiện, thường là tên ứng dụng hoặc thành phần con của nó.
- **Event Identifiers (Event ID)**: mã định danh duy nhất cho mỗi loại sự kiện.
- **Event Log Record**: bản ghi lưu trữ thời gian, loại sự kiện, danh mục...
- **Event Data**: dữ liệu đặc thù đính kèm sự kiện, kích thước tối đa `0x3FFFF` byte.

### Cách xem

- **Event Viewer (GUI)**: `eventvwr.msc` → duyệt theo channel, dùng "Filter Current Log" để lọc theo Event ID.
- **PowerShell**:
  ```powershell
  Get-WinEvent -LogName Security -MaxEvents 50
  Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}
  ```

### Các Event ID hay gặp khi điều tra

| Event ID | Ý nghĩa |
|---|---|
| 4624 | Đăng nhập thành công |
| 4625 | Đăng nhập thất bại |
| 4634 | Đăng xuất |
| 4688 | Tạo process mới (cần bật audit riêng) |
| 4720 | Tạo user account mới |
| 4732 | Thêm thành viên vào security group (local) |
| 4648 | Đăng nhập bằng credential tường minh (explicit logon — ví dụ `runas`) |
| 4672 | Gán đặc quyền admin (special privileges) cho phiên đăng nhập |
| 7045 | Cài đặt service mới (ghi ở channel System) — thường bị attacker lợi dụng cho persistence |

### LogonType

`LogonType` là mã số xác định phương thức mà người dùng/dịch vụ/máy tính kết nối và xác thực vào hệ thống — là trường trong Event 4624/4625 cho biết đăng nhập diễn ra theo cách nào. Full cheat sheet:

| Type | Tên | Ý nghĩa |
|---|---|---|
| 2 | Interactive | Đăng nhập trực tiếp tại bàn phím/màn hình máy (local hoặc domain account). |
| 3 | Network | Đăng nhập qua mạng — phổ biến nhất khi truy cập share/printer, không có phiên desktop. |
| 4 | Batch | Session được tạo khi Windows chạy scheduled task dưới quyền user chỉ định. |
| 5 | Service | Tương tự Batch nhưng dành cho service — khi service khởi động, Windows tạo logon session type 5. |
| 7 | Unlock | Khi user quay lại workstation và unlock màn hình khóa. |
| 8 | NetworkCleartext | Giống type 3 nhưng password gửi dạng cleartext qua mạng (ví dụ IIS basic authentication). |
| 9 | NewCredentials | Khi dùng `RunAs /netonly` để chạy chương trình dưới tài khoản khác. |
| 10 | RemoteInteractive | Đăng nhập qua RDP / Terminal Services / Remote Assistance. |
| 11 | CachedInteractive | Đăng nhập bằng credential cache (hash của 10 lần đăng nhập domain gần nhất) khi không có kết nối tới domain controller — hay gặp ở laptop. |

> Trong 3 type hay gặp nhất khi soi log: **Type 2** là ai đó ngồi trực tiếp gõ bàn phím, **Type 3** là truy cập qua mạng (SMB, share...), **Type 10** là RDP — cực kỳ đáng chú ý nếu xuất hiện ngoài giờ hành chính hoặc từ IP lạ.

## 2. Process và Process Tree

**Process** là một chương trình đang chạy, có không gian bộ nhớ và tài nguyên riêng — không dùng chung vùng nhớ, không truy cập trực tiếp dữ liệu của nhau.

Vì các process không thể trực tiếp truy cập vùng nhớ của nhau, muốn giao tiếp thì phải làm gián tiếp qua cơ chế gọi là **Inter-process communication (IPC)**:

- **Sockets and pipes**: giao tiếp qua network — UDP, TCP, RESTful API, hoặc message broker như RabbitMQ, Kafka...
- **Remote procedure calls**: thông qua gRPC.
- **Shared memory**.

**Thread**: đơn vị thực thi nhỏ hơn bên trong 1 process — một process có thể có nhiều thread chạy song song, chia sẻ chung bộ nhớ.

**Service**: một loại process đặc biệt chạy nền, không cần người dùng đăng nhập, thường khởi động cùng hệ thống và quản lý bởi Service Control Manager (`services.exe`). Service thường mặc định chạy trên Main Thread của process chứa nó.

### File thực thi vs Tiến trình

| Tiêu chí | File thực thi (Executable File) | Tiến trình (Process) |
|---|---|---|
| Trạng thái | Tĩnh (Passive) | Động (Active) |
| Vị trí lưu trữ | Ổ cứng (Disk / HDD / SSD) | Bộ nhớ trong (RAM) |
| Bản chất | Tệp chứa tập lệnh và dữ liệu, nằm chờ để chạy | Thực thể đang hoạt động, được OS quản lý và CPU thực thi |
| Thời gian tồn tại | Lâu dài (tồn tại đến khi bị xóa) | Tạm thời (biến mất khi đóng chương trình) |
| Tài nguyên tiêu thụ | Chỉ chiếm dung lượng lưu trữ | Tiêu tốn RAM, chu kỳ CPU, tài nguyên mạng, I/O... |
| Mối quan hệ | 1 file thực thi có thể tạo ra nhiều tiến trình | Mỗi tiến trình bắt nguồn từ 1 file thực thi |
| Ví dụ | `chrome.exe`, `word.exe`, `script.sh` | Mở 5 tab Chrome → nhiều tiến trình chạy ngầm trong Task Manager/htop |

### Parent/child process relationship

Mỗi process khi được tạo ra đều có một "process cha" — chính là process đã gọi lệnh tạo ra nó. Ví dụ: user mở Word → Word là con của `explorer.exe`; nếu Word bị khai thác và tự sinh ra `powershell.exe`, thì `powershell.exe` là con của `WINWORD.EXE`.

⇒ Nếu tiến trình cha bị kill, tiến trình con sẽ trở thành con của tiến trình hệ thống, thường là `init` hoặc `systemd`, có PID = 1.

**Xem cả chuỗi (process tree), không chỉ tên process**, vì tên process một mình không nói lên điều gì — `powershell.exe` hoàn toàn hợp lệ khi được gọi từ Task Scheduler hay từ user, nhưng **cực kỳ đáng ngờ** nếu process cha là `WINWORD.EXE` hoặc `OUTLOOK.EXE` — dấu hiệu điển hình của mã độc macro. Nhìn chuỗi cha-con giúp phát hiện những hành vi bất thường mà chỉ nhìn tên process riêng lẻ sẽ bỏ sót.

### Process hệ thống Windows bình thường chạy từ đâu

- `svchost.exe` — nằm trong `C:\Windows\System32\`, process cha là `services.exe`.
- `lsass.exe` — nằm trong `C:\Windows\System32\`, process cha là `wininit.exe`, chỉ có **duy nhất 1 instance** đang chạy.
- `explorer.exe` — nằm trong `C:\Windows\`, process cha thường là `userinit.exe` (hoặc không có cha rõ ràng sau khi userinit.exe thoát).

**Dấu hiệu bất thường trong process tree:**

- Process hệ thống chạy từ đường dẫn lạ (`svchost.exe` ngoài System32).
- Process cha không hợp lý (Word/Excel/Outlook spawn `cmd.exe`/`powershell.exe`).
- Nhiều instance của process lẽ ra chỉ có 1 (nhiều `lsass.exe`).
- Process không có chữ ký số (unsigned) chạy từ `%TEMP%`, `%APPDATA%`.

Bảng process hệ thống Windows chuẩn để đối chiếu khi nghi ngờ:

| Tiến trình | Đường dẫn chuẩn | Tiến trình cha chuẩn | Tài khoản | Số lượng chuẩn |
|---|---|---|---|---|
| System Idle Process | N/A (bộ nhớ kernel) | N/A (PID 0) | SYSTEM | 1 |
| System | N/A (bộ nhớ kernel) | System Idle Process (PID 0) | SYSTEM | 1 (PID 4) |
| smss.exe | `C:\Windows\System32\` | System (PID 4) | SYSTEM | 1 Master instance (instance con tự thoát sau khi tạo session) |
| csrss.exe | `C:\Windows\System32\` | smss.exe (thường đã thoát nên không thấy cha) | SYSTEM | ≥ 2 (1 cho Session 0, 1 cho Session 1+) |
| wininit.exe | `C:\Windows\System32\` | smss.exe (đã thoát) | SYSTEM | Duy nhất 1 |
| services.exe | `C:\Windows\System32\` | wininit.exe | SYSTEM | Duy nhất 1 |
| winlogon.exe | `C:\Windows\System32\` | smss.exe (đã thoát) | SYSTEM | ≥ 1 (1 cho mỗi user session) |
| spoolsv.exe | `C:\Windows\System32\` | services.exe | SYSTEM | 1 |
| taskhostw.exe | `C:\Windows\System32\` | svchost.exe | SYSTEM, User, Network Service... | Nhiều |
| conhost.exe | `C:\Windows\System32\` | Các tiến trình console (`cmd.exe`, `powershell.exe`...) | Khớp với tiến trình gọi nó | Nhiều (tương ứng số cửa sổ console) |

### Đọc kết quả `ps aux` trên Linux

- **USER**: tài khoản sở hữu và khởi chạy tiến trình.
- **PID**: mã định danh duy nhất của tiến trình — quan trọng nhất khi cần can thiệp (ví dụ `kill <PID>`).
- **%CPU**: tỷ lệ % năng lực CPU mà tiến trình đang dùng.
- **%MEM**: tỷ lệ % RAM vật lý mà tiến trình đang chiếm.
- **VSZ (Virtual Memory Size)**: tổng bộ nhớ ảo (KB) OS đã cấp phát, gồm cả thư viện động và vùng nhớ chưa dùng tới.
- **RSS (Resident Set Size)**: RAM vật lý thực tế (KB) tiến trình đang dùng ngay lúc này (không tính Swap).
- **TTY**: cửa sổ terminal đang kiểm soát tiến trình; dấu `?` nghĩa là tiến trình chạy ngầm (background/daemon), không gắn với terminal nào.
- **STAT**: trạng thái hoạt động — `S` (Interruptible Sleep, đang chờ event), `R` (Running/Runnable), `s` (Session Leader), `l` (Multi-threaded), `+` (Foreground).
- **START**: thời điểm tiến trình bắt đầu chạy.
- **TIME**: tổng thời gian CPU tiến trình đã thực sự dùng để xử lý tác vụ (không phải thời gian tồn tại).
- **COMMAND**: câu lệnh/đường dẫn đã tạo ra tiến trình, kèm toàn bộ tham số.

## 3. File System

| Thư mục | Vị trí chuẩn | Vai trò & điểm đáng lưu ý |
|---|---|---|
| System32 | `C:\Windows\System32\` | Chứa file thực thi (`.exe`), thư viện động (`.dll`) và driver 64-bit cốt lõi của OS. Lưu ý: dù tên là System32 nhưng trên Windows 64-bit, đây là nơi chứa ứng dụng 64-bit. |
| SysWOW64 | `C:\Windows\SysWOW64\` | Chứa file hệ thống 32-bit, giúp ứng dụng 32-bit cũ chạy trơn tru trên Windows 64-bit qua cơ chế WoW64. |
| Registry Config | `C:\Windows\System32\config\` | Nơi lưu trữ vật lý của các Registry Hives quản lý toàn bộ cấu trúc hệ thống. |
| Event Logs | `C:\Windows\System32\winevt\Logs\` | Chứa toàn bộ file nhật ký sự kiện Windows định dạng `.evtx` (System, Security, Application...). |
| Drivers & Etc | `C:\Windows\System32\drivers\etc\` | Chứa cấu hình mạng cục bộ (nổi bật là file `hosts`). Thư mục cha `drivers` chứa file `.sys` giao tiếp phần cứng và kernel. |
| AppData | `C:\Users\<username>\AppData\` | Chia 3 thư mục con: `Local`, `LocalLow`, `Roaming` — lưu dữ liệu/cấu hình riêng từng ứng dụng. **Điểm nóng**: mã độc (Ransomware, Stealer) rất thích ẩn ở `AppData\Local\Temp` vì user thường có toàn quyền ghi mà không cần quyền Admin. |
| ProgramData | `C:\ProgramData\` | Thư mục ẩn lưu dữ liệu ứng dụng chung cho tất cả người dùng trên máy. |

**Thư mục attacker thường lợi dụng để drop file:**

- `%TEMP%` / `C:\Windows\Temp`
- `%APPDATA%` / `%LOCALAPPDATA%`
- `C:\Users\Public\`
- `C:\ProgramData\`
- `C:\Windows\Tasks` hoặc các thư mục Startup

> Lý do: đây là những thư mục user thường (không cần quyền admin) có quyền ghi, và ít được để ý bằng System32.

**Vì sao file tên `svchost.exe` nằm ngoài System32 lại đáng ngờ**: vì `svchost.exe` hợp lệ luôn nằm cố định tại `C:\Windows\System32\svchost.exe` — đây là kỹ thuật **masquerading** (giả danh) kinh điển: attacker đặt tên file độc hại trùng tên process hệ thống quen thuộc để đánh lừa người xem log/task manager khi lướt qua nhanh, nhưng đường dẫn (path) lại không khớp với vị trí gốc — đây chính là điểm mấu chốt để phát hiện giả mạo.

Trên **Linux**, attacker luôn ưu tiên giấu mã độc tại các thư mục world-writable (`/tmp`, `/var/tmp`, `/dev/shm`) để thực thi nhanh gọn né rà quét, hoặc chôn sâu vào user-space (`~/.config`, `~/.bashrc`) để duy trì sự hiện diện tàng hình và bền bỉ nhất.

## 4. Linux Log

Log ghi lại các thông báo về hoạt động của cả hệ thống hoặc của các dịch vụ được triển khai trên hệ thống, cung cấp thời gian của các sự kiện cho hệ điều hành, ứng dụng và hệ thống Linux.

Mỗi ứng dụng cài trên hệ thống có cơ chế tạo log riêng. Trên Linux, log được tập trung tại thư mục `/var/log/`, chứa hầu hết các file log như access log, error log, app log, service log, system log...

**Cấu trúc một dòng log Linux điển hình** (theo chuẩn syslog): `timestamp` → `hostname` → `tên tiến trình[PID]` → `nội dung message`. Ví dụ:

```
Jul 6 10:15:22 ubuntu-vm sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 51000 ssh2
```

- **`/var/log/auth.log`**: chứa thông tin xác thực trên hệ thống, cơ chế ủy quyền của người dùng. Giúp xác định các lần đăng nhập thất bại hay kiểm tra tấn công và lỗ hổng liên quan.
- **`/var/log/secure`**: (trên các bản RHEL/CentOS) tương đương `auth.log` — lưu thông tin xác thực, đăng nhập sudo, SSH, mật khẩu thất bại, user không tồn tại...
- **`/var/log/kern.log`**: các thông tin ghi bởi kernel — giúp khắc phục lỗi và cảnh báo liên quan đến kernel.
- **`/var/log/syslog`**: log tổng hợp của hệ thống và nhiều dịch vụ khác nhau (không chỉ riêng auth) — nơi tổng quát để tìm sự kiện hệ thống nói chung.

**Syslog** (System Logging Protocol) là giao thức client/server dùng để chuyển log và thông điệp đến máy nhận log — thường gọi là `syslogd`, syslog daemon hoặc syslog server. Syslog có thể gửi qua UDP hoặc TCP, dữ liệu gửi dạng **cleartext**, dùng **port 514**.

Trong hệ thống Linux dùng **systemd**, việc ghi nhận và quản lý log đã được đơn giản hóa và tập trung hơn nhiều so với trước đây (khi log bị phân tán và xử lý bởi các daemon riêng lẻ như `rsyslog`, `syslog-ng`). Systemd cung cấp giải pháp quản lý nhật ký tập trung gọi là **journal**: toàn bộ log từ kernel, initrd, các daemon và ứng dụng người dùng đều được thu thập qua daemon `systemd-journald`.

Công cụ để truy cập và thao tác dữ liệu trong journal là **`journalctl`**:

```bash
journalctl -u ssh          # Xem log của 1 service cụ thể (hoặc sshd, tuỳ bản phân phối)
journalctl -u ssh -f       # Theo dõi log real-time
journalctl --since "1 hour ago"   # Lọc theo khoảng thời gian
```

> Ref: [101-linux-commands — the-journalctl-command](https://github.com/bobbyiliev/101-linux-commands/blob/main/ebook/en/content/139-the-journalctl-command.md)

## 5. SSH

**SSH (Secure Shell)** là giao thức mạng đảm bảo an toàn cho các kết nối từ xa. Cơ chế bảo mật của SSH dựa trên 3 trụ cột chính: **Mã hóa** dữ liệu để chống nghe lén, **Xác thực** để định danh người dùng/máy chủ, và **Toàn vẹn** dữ liệu để ngăn gói tin bị chỉnh sửa trên đường truyền.

### Kiến trúc mã hóa (Cryptography)

- **Mã hóa bất đối xứng (Asymmetric Encryption)**: dùng cặp khóa (công khai + bí mật) trong giai đoạn trao đổi khóa ban đầu (ví dụ thuật toán Diffie-Hellman) để thiết lập kênh giao tiếp an toàn mà không cần truyền khóa trực tiếp.
- **Mã hóa đối xứng (Symmetric Encryption)**: sau khi kênh an toàn được tạo, SSH chuyển sang mã hóa đối xứng (AES, ChaCha20) để mã hóa toàn bộ dữ liệu truyền tải trong phiên — giúp tăng tốc xử lý.
- **Hàm băm (Hashing - MAC)**: dùng HMAC để tạo chữ ký cho mỗi gói tin, đảm bảo gói tin không bị thay đổi hoặc giả mạo.

### Các phương thức xác thực

- **Xác thực bằng mật khẩu**: người dùng nhập mật khẩu, server xác thực dựa trên hash đã lưu. Dễ bị tấn công dò mật khẩu (brute-force).
- **Xác thực bằng cặp khóa (Key-based Authentication)**: dùng SSH Key — Public Key để trên Server, Private Key để trên máy Client. Phương thức an toàn và được khuyến nghị hàng đầu vì khóa có độ dài lớn, khó bị đoán trúng.

### Quy trình thiết lập kết nối (Connection Flow)

1. **Thương lượng giao thức**: Client và Server thống nhất phiên bản SSH (hiện chủ yếu SSH-2) và thuật toán mã hóa.
2. **Trao đổi khóa & xác thực máy chủ**: Client xác minh danh tính Server qua vân tay (fingerprint) để tránh tấn công Man-in-the-Middle.
3. **Xác thực người dùng**: Client chứng minh có quyền truy cập Server (mật khẩu hoặc SSH Key).
4. **Mở phiên làm việc**: kênh truyền được mã hóa hoàn toàn, các lệnh từ Client sang Server được thực thi.

`authorized_keys` là file nằm tại `~/.ssh/authorized_keys` trên server, chứa danh sách các public key được phép đăng nhập vào tài khoản đó **mà không cần mật khẩu**.

**Vì sao attacker thường nhắm vào file này**: nếu attacker chèn được public key của họ vào `authorized_keys` của một user (đặc biệt user quyền cao), họ sẽ có đường **backdoor SSH lâu dài** — đăng nhập lại bất cứ lúc nào mà không cần biết mật khẩu, và hành vi này rất dễ bị bỏ sót nếu không kiểm tra định kỳ nội dung file.

**Dấu vết SSH login thành công để lại trong log**: trong `/var/log/auth.log` sẽ có dòng dạng `Accepted password for <user> from <IP> port <port> ssh2` hoặc `Accepted publickey for <user> from <IP> ...`, kèm theo sau đó là dòng ghi nhận phiên `pam_unix(sshd:session): session opened for user <user>`.

## 6. Persistence phổ biến

### Trên Windows

- **Scheduled Task (MITRE T1053.005)** — tạo tác vụ tự động chạy script/chương trình theo lịch hoặc trigger (login, khởi động máy...) — dùng `schtasks` hoặc Task Scheduler.
  > Dấu vết: Security Log - Event ID 4698, 4699/4702; Task Scheduler Log - Event ID 106 · `C:\Windows\System32\Tasks\` · `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`

- **Registry Run Key & Startup Folder (MITRE T1547.001)** — thêm giá trị/đường dẫn file độc hại vào các khóa như `HKCU\...\Run` hoặc `HKLM\...\Run` để chương trình tự chạy mỗi khi user đăng nhập.
  > Dấu vết: Sysmon - Event ID 12, 13, 14 · `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` · `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` · `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` · `AppData\Roaming\...`

- **Windows Service (MITRE T1543.003)** — cài đặt (mã độc) như một Windows Service (sinh Event ID 7045) qua lệnh `sc create` hoặc `New-Service`, chạy nền không cần đăng nhập, thường chạy với quyền SYSTEM.
  > Dấu vết: System Log - Event ID 7045; Security Log - Event ID 4697 · `HKLM\SYSTEM\CurrentControlSet\Services\<Tên_Dịch_Vụ>`

- **WMI Event Subscription (MITRE T1546.003 - Fileless Persistence)** — đăng ký sự kiện WMI (Event Filter + Event Consumer) để tự động thực thi mã khi một điều kiện hệ thống xảy ra — kỹ thuật khó phát hiện vì không để lại file rõ ràng trên đĩa, ít được giám sát mặc định.
  > Dấu vết: Sysmon - Event ID 19, 20, 21; Microsoft-Windows-WMI-Activity/Operational - Event ID 5861 · `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`

### Trên Linux

- **Cron Jobs (MITRE T1053.003) - crontab** — lên lịch chạy lệnh/script định kỳ (`crontab -e`, hoặc `/etc/cron.d/`) — attacker thêm dòng cron gọi lại payload theo chu kỳ.
  > Dấu vết: `/var/log/syslog` hoặc `/var/log/cron`

- **SSH Authorized Keys (MITRE T1098.004) - authorized_keys** — như đã nói ở trên, chèn public key để có quyền truy cập SSH lâu dài.
  > Dấu vết: `~/.ssh/authorized_keys` và `/root/.ssh/authorized_keys`

- **Systemd Service (MITRE T1543.002) - systemd service** — tạo file `.service` trong `/etc/systemd/system/` để chạy nền như 1 service hợp pháp, tự khởi động cùng hệ thống.
  > Dấu vết: `/etc/systemd/system/` hoặc `/usr/lib/systemd/system/` · User-level: `~/.config/systemd/user/`

- **Shell Configuration Files (.bashrc / .profile / .bash_profile) (MITRE T1546.004)** — chèn lệnh độc hại vào các file này khiến nó tự thực thi mỗi khi user mở shell mới.
  > Dấu vết: `~/.bashrc, ~/.bash_profile, ~/.profile, ~/.zshrc` và `/etc/profile, /etc/bash.bashrc,` và các script trong `/etc/profile.d/`

## Thực hành

### Lab 2.1 — Windows Event Log

Tạo người dùng test mới bằng GUI (`CMC CS` / `123`), hoặc bằng Command Prompt:

```
net user CMC 1234 /add
```

<img width="532" height="205" alt="image" src="https://github.com/user-attachments/assets/a98949b5-fae7-4d51-9f56-cb8c3b2784c2" />

Mở **Event Viewer → Filter Current Log**, lọc theo Event ID `4625` (Failed Logon) hoặc `4624` (Successful Logon):

- Bộ lọc **4625** cho thấy các lần đăng nhập thất bại.
- Bộ lọc **4624** cho thấy các lần đăng nhập thành công.

<img width="571" height="565" alt="image" src="https://github.com/user-attachments/assets/1709fe2f-6475-45cb-9dbc-c6920b300b93" />

Bóc tách chi tiết một event **4625** thực tế:

- **Loại sự kiện**: Đăng nhập thất bại (Logon Failure)
- **Thời gian**: 7/8/2026 8:34:06 AM
- **Máy tính**: DESKTOP-US7L6JU
- **Tài khoản bị lỗi**: CMC CS (Domain: DESKTOP-US7L6JU, SID: NULL SID)
- **Lý do thất bại**: Sai username hoặc password (Status `0xC000006D` / Sub Status `0xC000006A`)
- **Logon Type**: 2 (Interactive — đăng nhập trực tiếp)
- **Tiến trình gọi**: `svchost.exe` (PID `0x5d0`), chạy dưới quyền SYSTEM
- **Nguồn kết nối**: `127.0.0.1` (localhost) — không phải từ mạng ngoài
- **Authentication Package**: Negotiate, Logon Process: User32

<img width="1363" height="780" alt="image" src="https://github.com/user-attachments/assets/560cfc7a-a287-426f-9c6a-039332a15fe2" />

Chuyển qua tab **Details → XML View** để xem raw data. Một điểm rất hay bị hiểu nhầm khi đọc XML:

Thẻ `<Level>` trong `<System>` biểu thị mức độ nghiêm trọng (severity) của sự kiện:

| Giá trị | Ý nghĩa |
|---|---|
| 0 | LogAlways (thường hiển thị là "Information") |
| 1 | Critical |
| 2 | Error |
| 3 | Warning |
| 4 | Information |
| 5 | Verbose |

Trong log ví dụ: `<Level>0</Level>` → tương ứng "Level: Information" hiển thị ở tab General.

**Điểm hay bị hiểu nhầm:**

- Nhiều người thấy Event 4625 là "logon failure" nên nghĩ Level phải là Warning/Error — nhưng thực tế Windows luôn gán **Level = 0 (Information)** cho hầu hết các Security Audit event (bao gồm cả logon failure), vì đây là **audit log**, không phải system health log.
- Mức độ "nghiêm trọng" thực sự của một audit event được thể hiện qua **Keywords** (`Audit Success` / `Audit Failure`) chứ không phải qua Level.
- Trong log này: `<Keywords>0x8010000000000000</Keywords>` → decode ra là **Audit Failure**, đây mới là cờ cho biết "đây là một lần thất bại", khớp với "Keywords: Audit Failure" ở tab General.

<img width="1193" height="859" alt="image" src="https://github.com/user-attachments/assets/f21bce96-f59d-4f1d-86e6-9112b8058146" />

Khi nào nên dùng General, khi nào nên dùng XML:

| Mục đích | Nên dùng |
|---|---|
| Xem nhanh "chuyện gì đã xảy ra" | General |
| Điều tra sâu, xác minh danh tính chính xác (SID) | XML |
| Liên kết nhiều event thành chuỗi hành động | XML (ActivityID) |
| Đưa dữ liệu vào công cụ phân tích/SIEM/script | XML |
| Báo cáo nhanh cho người không chuyên | General |

Xem event bằng PowerShell qua `Get-WinEvent`, có thể xuất luôn ra CSV để lưu và mở bằng Excel:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10 | Format-List TimeCreated, Id, Message

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | Export-Csv -Path C:\Users\Public\failed_logons.csv -NoTypeInformation
```

<img width="1206" height="877" alt="image" src="https://github.com/user-attachments/assets/02e8699c-ec91-4a80-b9b4-38793ea7d754" />

### Lab 2.2 — Linux Log

Thử SSH và đăng nhập nhiều lần với mật khẩu sai, cả với user tồn tại (`bao`) lẫn user không tồn tại (`cmc`, `admin`), sau đó login thành công để tạo ra một bộ log SSH/PAM đầy đủ. Xem 50 dòng cuối của log xác thực:

```bash
sudo tail -n 50 /var/log/auth.log
```

<img width="1276" height="809" alt="image" src="https://github.com/user-attachments/assets/d00385c9-321e-4177-828b-965306d7e207" />

**Phân tích log `/var/log/auth.log` (SSH/PAM)** — máy bị "tấn công" từ `192.168.1.133`, đọc theo timeline:

- **02:15:03** — Đăng nhập local hợp lệ: user `bao` login thành công qua console (`login[1040]`), session 1 mở.
- **02:15:21 → 02:15:32** — Brute-force vào user `bao` (có thật): 3 lần sai password liên tiếp từ `192.168.1.133:51523` (ssh2), bị reset kết nối do quá nhiều lần thất bại (`PAM 2 more authentication failures`).
- **02:15:37** — Đăng nhập SSH thành công vào `bao`: `Accepted password for bao from 192.168.1.133 port 51525` → **kẻ tấn công đã đoán đúng password và vào được!** Session 3 mở ra cho user bao.
- **02:16:36** — Ngắt kết nối, đóng session 3.
- **02:16:49 → 02:17:00** — Brute-force tiếp vào user `cmc` (không tồn tại): `Invalid user cmc` → nhiều lần thử sai password cho user không có thật, bị reset kết nối sau nhiều lần thất bại.
- **02:17:06 → 02:17:14** — Brute-force vào user `admin` (không tồn tại): tương tự — thử nhiều lần rồi bị reset.
- **02:18:14** — Đăng nhập SSH thành công lần 2 vào `bao`: `Accepted password for bao from 192.168.1.133` → kẻ tấn công đăng nhập lại lần nữa, session 5 mở.
- **02:19:05** — Thử sudo thất bại: `sudo: pam_unix(sudo:auth): authentication failure` cho user bao khi chạy sudo.
- **02:19:09** — Thử sudo thành công, đọc log auth: `COMMAND=/usr/bin/tail -n 50 /var/log/auth.log` → **kẻ tấn công dùng quyền root để đọc chính log này** (có thể để xóa dấu vết hoặc kiểm tra bị phát hiện chưa).


Dùng `grep` để lọc theo keyword `Failed password` và `Invalid user`, hoặc dùng `journalctl`:

```bash
sudo grep "Failed password" /var/log/auth.log
sudo grep "Invalid user" /var/log/auth.log
journalctl -u ssh | grep "Failed password"
```

Đếm số lần thất bại/thành công theo user và theo IP nguồn:

```bash
sudo grep "Failed password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c
sudo grep "Failed password" /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort | uniq -c
sudo grep "Accepted password" /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort | uniq -c
sudo grep "Accepted password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c
```


- **Thất bại**: chứa cụm `Failed password for` hoặc `Invalid user`.
- **Thành công**: chứa cụm `Accepted password for` hoặc `Accepted publickey for`, thường theo sau là dòng `pam_unix(sshd:session): session opened for user`.

### Lab 2.3 — Process và kết nối mạng

Xem tiến trình bằng **Task Manager → Details** (chú ý cột PID, Status, User name) hoặc bằng PowerShell:

```powershell
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Name, CPU, Id
```

Xem kết nối mạng theo port, tham chiếu PID (`OwningProcess`) để biết service nào đang sử dụng:

```powershell
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
```

Hoặc dùng `netstat -ano` để xem nhanh trạng thái (State), địa chỉ nguồn/đích và cổng kết nối:

```
netstat -ano
```


Dùng thêm công cụ **Process Explorer** (Sysinternals) để soi sâu hơn:

- Vào **Options → Select Columns** để bật thêm các cột quan trọng: **Path**, **Command Line**, **Autostart Location**... giúp phát hiện những bất thường (ví dụ process chạy từ đường dẫn lạ, hoặc autostart location đáng ngờ).
- Chọn **View → Show Process Tree** để xem toàn bộ chuỗi cha-con.
- **Click đúp** vào một process để xem chi tiết: Image (Path, Command line, Autostart Location, Parent), TCP/IP (kết nối mạng của riêng process đó), và đặc biệt tab **Strings** — rất quan trọng để đọc các metadata/chuỗi ký tự nhúng trong tiến trình, giúp phát hiện dấu hiệu bất thường mà tên process không nói lên được.

<img width="1909" height="874" alt="image" src="https://github.com/user-attachments/assets/47591c57-11e3-4d7b-96f2-eaffe4e583f9" />

Trên **Linux**, kiểm tra các thư mục "nhạy cảm" mà attacker hay lợi dụng:

```bash
ls -la /tmp
ls -la /dev/shm

# Tìm file được tạo/sửa trong N phút gần nhất trên toàn hệ thống (soi dấu vết mới)
find /tmp /dev/shm -newermt "5 minutes ago" -type f
```


### Lab 2.4 — Persistence mô phỏng

**Trên Windows.** Tạo file test đơn giản `C:\Users\Public\test.ps1`:

```powershell
Add-Content -Path C:\Users\Public\log.txt -Value "task ran at $(Get-Date)"
```

`Add-Content` ghi thêm 1 dòng vào file `log.txt`, kèm thời gian hiện tại (`Get-Date`) — mục đích là có bằng chứng trực quan xác nhận task đã thực sự chạy.

Tạo scheduled task bằng PowerShell (chạy as Administrator), tương ứng kỹ thuật persistence **T1053.005 (Scheduled Task/Job)** trong MITRE ATT&CK:

```
schtasks /create /tn "TestPersistence" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\test.ps1" /sc onlogon /ru SYSTEM
```

| Tham số | Ý nghĩa |
|---|---|
| `/create` | Tạo một scheduled task mới |
| `/tn "TestPersistence"` | Task Name — tên định danh của task trong hệ thống |
| `/tr "..."` | Task Run — lệnh sẽ được thực thi khi task kích hoạt |
| `powershell.exe -ExecutionPolicy Bypass -File C:\...\test.ps1` | Gọi PowerShell chạy file script, kèm `-ExecutionPolicy Bypass` để bỏ qua chính sách chặn script mặc định của Windows — đây chính là dòng mà attacker thật sự hay dùng, vì mặc định Windows chặn chạy `.ps1` |
| `/sc onlogon` | Schedule — trigger: chạy mỗi khi có ai đăng nhập vào máy |
| `/ru SYSTEM` | Run as User — chạy với tài khoản SYSTEM (quyền cao nhất hệ thống, không cần mật khẩu) — đây là điểm rất đáng ngờ nếu gặp trong thực tế, vì user thường không có lý do gì để tạo task chạy bằng SYSTEM |

Đăng xuất/đăng nhập lại (hoặc chạy `schtasks /run /tn "TestPersistence"`) để trigger task.


Kiểm tra task có thực sự chạy không (độc lập với log), xem trường **Last Run Time** và **Last Result** — nếu Last Result = `0` nghĩa là task đã chạy thành công, kèm kiểm tra file kết quả để chắc chắn log đã được ghi:

```
schtasks /query /tn "TestPersistence" /v /fo list
Get-Content C:\Users\Public\log.txt
```

`/query` truy vấn thông tin task; `/v` verbose (chi tiết đầy đủ, gồm cả Last Run Time, Last Result); `/fo list` format output dạng danh sách dễ đọc thay vì bảng.


Mở **Event Viewer → Applications and Services Logs → Microsoft → Windows → TaskScheduler → Operational**. Khi persistence được thực thi, nó tạo ra 1 log Warning và 6 log Information — đọc theo đúng chuỗi sự kiện:

- **Event ID 325** (Warning) — Yêu cầu chạy, kích hoạt bởi SYSTEM — test chạy task theo trigger. Task `\TestPersistence` được thực thi.
- **Event ID 129** (Info) — Đã tạo tiến trình nhiệm vụ. Nguồn là dịch vụ TaskScheduler bởi user SYSTEM. Tiến trình được tạo ra bởi task `\TestPersistence` là `powershell.exe` với PID cụ thể.
- **Event ID 100** (Info) — Task được bắt đầu (started), không chỉ dừng ở queue — chạy dưới quyền `NT AUTHORITY\SYSTEM` (quyền cao nhất trên máy). Instance ID khớp với event 325 trước đó → cùng một lần chạy.
- **Event ID 200** (Info) — Thực thi action = `powershell.exe`, chạy dưới quyền SYSTEM ⇒ thông thường cần tìm xem command line này chạy với tham số và lệnh gì.
- **Event ID 110** (Info) — Task được trigger. Task Category = "Task triggered by user" — lưu ý chữ "by user" ở đây chỉ là tên category chuẩn của Windows, **không có nghĩa là có người dùng thật đứng ra bấm chạy**; thực ra trigger có thể là logon, schedule, hoặc do bị gọi bằng lệnh `schtasks /run`.
- **Event ID 201** (Info) — Action được hoàn thành: task đã chạy thành công, script PowerShell thực thi không gặp lỗi và `return 0`.
- **Event ID 102** (Info) — Task hoàn thành: `\TestPersistence` được thực thi thành công/hoàn thành bởi user SYSTEM.

<img width="1909" height="868" alt="image" src="https://github.com/user-attachments/assets/66724a7b-6bb9-488b-96d0-d86005c96d6d" />

Đối chiếu bằng **Process Explorer**: bắt được tiến trình `powershell.exe` xuất hiện đúng lúc task được trigger — nó là tiến trình con của `svchost.exe` (thông qua Task Scheduler service) và là tiến trình cha của `conhost.exe`. Chuỗi cha-con này khớp hoàn toàn với những gì log Event Viewer đã ghi lại.

<img width="528" height="214" alt="image" src="https://github.com/user-attachments/assets/a8e24879-07b7-4d92-bed5-6cc54e6bc9b5" />

Dọn dẹp sau khi test:

```
schtasks /delete /tn "TestPersistence" /f
```

**Trên Linux.** Tạo crontab cho user hiện tại:

```bash
crontab -e
```

Lệnh này mở trình soạn thảo để chỉnh crontab của user hiện tại (không phải file hệ thống dùng chung — mỗi user có crontab riêng). Thêm dòng sau để mô phỏng payload chạy mỗi phút:

```
* * * * * echo "cron ran at $(date)" >> /tmp/cron_test.log
```

5 dấu `*` đầu là lịch chạy theo thứ tự: **phút — giờ — ngày trong tháng — tháng — thứ trong tuần**. Dấu `*` nghĩa là "mọi giá trị" → cả 5 đều là `*` nghĩa là chạy **mỗi phút, không giới hạn gì**. Phần sau lệnh thực thi ghi thêm (`>>`) dòng chữ kèm thời gian vào file log — payload giả lập tương tự bên Windows.

→ Tương ứng kỹ thuật **T1053.003 (Cron)** trong MITRE ATT&CK. Trong thực tế, attacker thường thay `echo` bằng lệnh tải và chạy payload từ xa (`curl ... | bash`), và thường đặt lịch chạy lâu lâu 1 lần (ví dụ mỗi giờ) để tránh gây chú ý thay vì mỗi phút.


Chờ 1-2 phút rồi kiểm tra:

```bash
grep CRON /var/log/syslog
# hoặc
sudo journalctl -u cron

cat /tmp/cron_test.log
```

Xác nhận thấy dòng log ghi nhận cron đã kích hoạt job theo đúng chu kỳ đặt ra, và file `/tmp/cron_test.log` đã có nội dung ghi vào đúng như mong đợi.


---

Tuần 2 khép lại với một bộ khung khá đầy đủ để đọc hiểu log Windows/Linux, phân biệt process bình thường với process đáng ngờ, và nhận diện các kỹ thuật persistence phổ biến theo MITRE ATT&CK. Phần lab brute-force SSH + Scheduled Task/Cron persistence ở trên là dạng bài tập nên làm đi làm lại — tự tay tạo ra "tấn công" rồi tự soi log của chính mình là cách học DFIR nhanh nhất.

Peace!
