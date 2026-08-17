---
title: "Tuần 1 — Network Foundation"
date: 2026-08-17 10:00:00 +0700
categories: [network]
tags: [networking, osi, tcp-ip, dns, nat, dhcp, wireshark, soc]
---

Tuần đầu tiên mình dành để ôn lại nền tảng networking — thứ mà ae làm security nào cũng cần nắm chắc trước khi đi sâu vào các mảng khác. Note lại đây để sau này cần thì lật ra xem lại, kèm vài cái lab thực hành nho nhỏ với Wireshark, nslookup, dig, netstat, nmap.

## 1. Mô hình OSI - 7 tầng

### Tầng vật lý (Physical)

- Chuyển tiếp dữ liệu từ nguồn đến đích (data ở dạng các bit 0/1).
- Biểu diễn bit: chuyển từ các bit 0/1 thành tín hiệu vật lý.
- Kiểm soát tốc độ truyền và đồng bộ hóa các bit.
- Cấu hình vật lý, các topo mạng, các chế độ truyền dẫn (simplex, half-duplex, full-duplex).
- Không toàn vẹn, không bảo mật.
- Thiết bị đại diện: **Hub**.

### Tầng liên kết dữ liệu (Data Link)

- Cung cấp cơ chế kiểm tra lỗi, kiểm soát truy cập.
- Đóng gói dữ liệu (framing), gán địa chỉ MAC, kiểm soát lưu lượng (flow control), kiểm soát lỗi.
- Thiết bị/khái niệm liên quan: NIC, Switch, ARP, CRC, CSMA/CD, CSMA/CA.

### Tầng mạng (Network)

- Truyền dữ liệu qua các chặng trung gian, qua nhiều mạng khác nhau.
- Định địa chỉ logic ⇒ gán IP.
- Định tuyến ⇒ Router (LAN, WAN), Firewall...

### Tầng giao vận (Transport)

- Phân mảnh / phân đoạn / tái hợp dữ liệu.
- Kiểm soát và duy trì kết nối giữa người gửi và người nhận.
- Kiểm soát lưu lượng, kiểm soát lỗi.
- Dùng PORT để chỉ định cổng dịch vụ.
- Giao thức tiêu biểu: TCP, UDP, Firewall...

### Tầng phiên (Session)

- Tạo kết nối giữa 2 thiết bị (duy trì, kiểm soát, đồng bộ hóa).
- Xác định loại giao tiếp.
- Giao thức tiêu biểu: SSL, TLS, Kerberos...

### Tầng trình diễn (Presentation)

- Chuyển đổi dữ liệu cho tầng trên hiểu được.
- Mã hóa và giải mã.
- Nén — giảm kích thước dữ liệu truyền đi.

### Tầng ứng dụng (Application)

- Cung cấp giao diện, dịch vụ cho người dùng.
- Tạo thiết bị đầu cuối, cho phép truy cập dịch vụ mạng.
- Quản lý, truy cập, truyền file.
- Giao thức tiêu biểu: SMTP, LDAP, HTTP...
- Thiết bị/dịch vụ liên quan: IDS, IPS, DHCP.

> Quá trình đóng gói dữ liệu (**Encapsulation**) diễn ra khi đi từ tầng Ứng dụng xuống tầng Vật lý bên gửi (thêm header/trailer ở mỗi tầng), và quá trình **Decapsulation** (giải nén, gỡ bỏ header/trailer) diễn ra ngược lại ở bên nhận. PDU đổi tên qua từng tầng: Data → Segment → Packet → Frame → Bit.

## 2. TCP vs UDP

| TCP | UDP |
|---|---|
| Truyền tin tin cậy, toàn vẹn, tốc độ chậm, theo thứ tự | Nhanh, không cần bắt tay, có thể mất mát gói tin trong quá trình truyền tải |
| Ứng dụng: Mail, Web, File... | Ứng dụng: Stream, Game online... |

Về cơ chế bắt tay 3 bước (3-way handshake) của TCP:

```
Client                          Server
  |----------- SYN (seq=m) --------->|
  |<-------- SYN+ACK (seq=n,-------- |
  |          ack=m+1) ---------------|
  |----------- ACK (ack=n+1) ------->|
```

Một điểm hay: **DNS lại dùng UDP** thay vì TCP, vì:

- Loại bỏ độ trễ của quá trình handshake — cần truy vấn domain ⇒ IP thật nhanh để truy cập tài nguyên.
- Gói tin DNS nhỏ, không cần cơ chế xác thực phức tạp như TCP.
- Tuy nhiên DNS không hoàn toàn "tẩy chay" TCP (một số trường hợp như zone transfer hay response quá lớn vẫn dùng TCP).

## 3. Port và Socket

- **Port** là địa chỉ giúp truy cập, truyền dữ liệu giữa các thiết bị/ứng dụng/dịch vụ, có giá trị từ 0–65535. Trạng thái thường gặp: khi có kết nối là `ESTABLISHED`, đang lắng nghe là `LISTEN`, đã đóng là `CLOSED`.
- **Socket** là điểm cuối (endpoint) của kết nối giữa Server và Client. Socket = địa chỉ IP + Port, ví dụ `192.168.1.1:8080`. Một kết nối TCP thực chất là một cặp socket (socket nguồn + socket đích).
- Địa chỉ IP giúp xác định **máy nào** trên mạng, port xác định **dịch vụ nào** trên máy đó.

Các port phổ biến cần nhớ:

| Dịch vụ | Port |
|---|---|
| HTTP | 80 |
| HTTPS | 443 |
| SSH | 22 |
| FTP | 20/21 |
| DNS | 53 |
| SMB | 445 |
| SMTP | 25 |

Lệnh xem port/kết nối đang mở:

```bash
netstat -ano   # Windows
ss -tulnp      # Linux
```

## 4. DNS

Hệ thống phân giải tên miền: chuyển đổi tên miền thành địa chỉ IP và ngược lại.

Các bước của một DNS lookup (đơn giản hóa):

1. Client kiểm tra cache cục bộ (cache trình duyệt, cache hệ điều hành, file hosts).
2. Nếu không có, client gửi truy vấn đến **recursive resolver** (thường là DNS server của ISP hoặc DNS công cộng như `8.8.8.8`).
3. Resolver hỏi **Root DNS server** để biết TLD server nào quản lý (`.com`, `.vn`...).
4. Resolver hỏi **TLD server** để tìm Authoritative Name Server của domain.
5. Resolver hỏi **Authoritative Name Server** để lấy bản ghi cần thiết (ví dụ: A record).
6. Resolver trả kết quả về cho client và lưu cache theo TTL.

**Recursive resolver** là server đứng ra "đi hỏi hộ" toàn bộ chuỗi (root → TLD → authoritative) thay cho client, rồi trả về kết quả cuối cùng — client chỉ cần hỏi một lần.

Các loại record DNS hay gặp:

| Record | Ý nghĩa |
|---|---|
| A | Ánh xạ địa chỉ IPv4 |
| AAAA | Ánh xạ địa chỉ IPv6 |
| MX | Chỉ định Mail Server nhận mail cho domain |
| TXT | Lưu văn bản, dùng để xác thực chống giả mạo |
| CNAME | Bí danh để trỏ 1 domain sang domain khác |
| PTR | Ánh xạ IP về domain (reverse lookup) |

Vài kiểu lạm dụng DNS đáng chú ý trong security:

- **DNS tunnelling**: che giấu dữ liệu / kênh C2 bên trong các truy vấn DNS.
- **DNS Spoofing / Poisoning**: chèn record giả để hướng nạn nhân tới domain độc hại.
- **DNS amplification**: lợi dụng DNS server mở (open resolver) để khuếch đại lưu lượng, phục vụ tấn công DDoS.

## 5. NAT

NAT (Network Address Translation) dùng để chuyển đổi từ IP private sang IP public, phục vụ định tuyến trên Internet. Có 3 loại chính:

- **Static NAT**: loại cơ bản nhất, ánh xạ cố định 1-1 giữa một địa chỉ IP tĩnh trong mạng cục bộ với một địa chỉ IP công cộng.
- **Dynamic NAT**: ánh xạ động giữa một dải IP nội bộ với một dải IP công cộng, cho phép nhiều thiết bị chia sẻ (luân phiên) một địa chỉ IP công cộng.
- **PAT (Port Address Translation)**: phổ biến nhất. Cho phép nhiều thiết bị trong mạng cục bộ dùng chung **một** địa chỉ IP công cộng, phân biệt nhau qua các port khác nhau. Giúp tiết kiệm IP công cộng và tăng bảo mật vì IP nội bộ không lộ ra ngoài.

Các dải địa chỉ IP private (RFC 1918):

- `10.0.0.0 – 10.255.255.255`
- `172.16.0.0 – 172.31.255.255`
- `192.168.0.0 – 192.168.255.255`

Một lưu ý quan trọng cho anh em làm điều tra sự cố: khi nhiều thiết bị dùng chung một địa chỉ NAT để ra Internet, cần **log NAT/firewall** để ánh xạ ngược lại sang `Internal IP : Port` — đây là cách truy vết nguồn gốc sự cố khi chỉ có IP public trong log.

## 6. DHCP

DHCP (Dynamic Host Configuration Protocol) là giao thức mạng dùng để tự động cấu hình địa chỉ IP cho các thiết bị kết nối vào mạng. Khi một thiết bị mới kết nối, DHCP server sẽ tự động cấp các thông số cần thiết: địa chỉ IP, subnet mask, default gateway và DNS server.

- Hoạt động ở tầng **Application** trong mô hình TCP/IP.
- Có 2 phiên bản: cho IPv4 và IPv6.
- Dùng port **67, 68**, chạy trên giao thức **UDP**.

DHCP hỗ trợ 3 cơ chế cấp địa chỉ IP:

- **Cấp tự động**: gán 1 địa chỉ IP thường trực cho 1 client.
- **Cấp động**: gán địa chỉ IP trong một khoảng thời gian hữu hạn (lease time).
- **Cấp thủ công**: địa chỉ IP được gán sẵn bởi người quản trị, DHCP chỉ có nhiệm vụ đưa địa chỉ đó đến client.

Có 2 mô hình triển khai chính:

- **DHCP tập trung (Centralized, có Relay Agent)**: dùng một hoặc một cụm máy chủ DHCP (Windows Server, Linux, Infoblox...) đặt tại phòng máy chủ trung tâm, cấp IP cho toàn bộ phòng ban/VLAN thông qua tính năng **DHCP Relay Agent** cấu hình trên Switch/Router.
- **DHCP phân tán (Distributed)**: mỗi chi nhánh/phòng ban tự chạy một máy chủ DHCP riêng, thường cấu hình ngay trên Switch Layer 3 hoặc Router/Firewall tại chỗ.

> Lưu ý bảo mật: doanh nghiệp luôn nên bật **DHCP Snooping** trên các switch để chống kẻ gian cắm Router/DHCP giả mạo vào mạng nội bộ (rogue DHCP).

## 7. CIA Triad và các khái niệm bảo mật cơ bản

**CIA Triad:**

- **Confidentiality (Bảo mật)**: chỉ người/hệ thống được phép mới truy cập được thông tin.
- **Integrity (Toàn vẹn)**: dữ liệu không bị thay đổi trái phép, đảm bảo tính chính xác.
- **Availability (Sẵn sàng)**: hệ thống/dữ liệu luôn sẵn sàng khi người dùng hợp pháp cần.

**Phân biệt các khái niệm hay bị nhầm:**

- **Vulnerability (Lỗ hổng)**: điểm yếu tồn tại trong hệ thống, phần mềm, hoặc quy trình.
- **Threat (Mối đe dọa)**: bất kỳ tác nhân/sự kiện nào có khả năng khai thác lỗ hổng để gây hại (hacker, malware, thiên tai...).
- **Risk (Rủi ro)**: khả năng thiệt hại thực tế xảy ra, thường được tính dựa trên xác suất threat khai thác được vulnerability nhân với mức độ ảnh hưởng: `Risk = Threat × Vulnerability × Impact`.
- **Exploit**: công cụ, đoạn mã, hoặc kỹ thuật cụ thể dùng để khai thác một vulnerability.

**SOC Tier 1 / 2 / 3:**

- **Tier 1 (Analyst)**: giám sát alert liên tục, triage ban đầu, phân loại True Positive/False Positive, escalate lên Tier 2 nếu cần, tuân theo playbook có sẵn.
- **Tier 2 (Incident Responder)**: điều tra sâu hơn các case được escalate, phân tích threat intelligence, xử lý incident phức tạp, đề xuất biện pháp ngăn chặn/khắc phục.
- **Tier 3 (Threat Hunter / Advanced Analyst)**: chủ động threat hunting, phân tích malware chuyên sâu, xây dựng use case/rule mới, xử lý các incident nghiêm trọng nhất, cải tiến quy trình SOC.

## Tài liệu tham khảo

- Window firewall rule: [video 1](https://www.youtube.com/watch?v=hqnEyGmMDcQ), [video 2](https://www.youtube.com/watch?v=we2pn7w-3IU&t=56s)
- Change SSH port: [video](https://www.youtube.com/watch?v=16DCYJ-ovsE) — nên đổi sang port trong khoảng 1024–65535 để tránh rủi ro.

## Thực hành

### Lab 1.1 — Kiểm tra kết nối giữa 2 máy

Setup: máy Win 10 (IP `192.168.1.133`, đã cài Wireshark) và máy Ubuntu Server 22.04 (IP `192.168.1.145`).

Ping từ Win 10 sang Ubuntu Server thành công, và ping ngược lại từ Ubuntu Server sang Win 10 cũng thành công — xác nhận 2 máy đã thông mạng với nhau, sẵn sàng cho các lab bắt gói tin ở phần sau.

*(Chèn ảnh: kết quả `ping` trên Command Prompt của Win 10 và trên terminal Ubuntu)*

### Lab 1.2 — Bắt gói tin với Wireshark

Thực hiện ping ra ngoài Internet, tạo thêm một số truy vấn: ping, nslookup, truy cập vài trang web, rồi mở Wireshark lên phân tích.

- **Lọc gói DNS**: thấy các domain được resolve như `google.com`, `instagram.com`, `xpaywalletcdn-prod.azureedge.net`, `p01.afd.azureedge.net`... đi kèm các record A và CNAME.
- **Lọc gói HTTP**: bắt được request `GET` và response trả về `200 OK`.
- **Lọc gói chứa cờ SYN** bằng filter:
  ```
  tcp.flags.syn == 1
  ```
- **Follow TCP Stream** để quan sát rõ quy trình bắt tay: 3 gói đầu tiên trong stream thực hiện 3-way handshake (SYN → SYN/ACK → ACK), từ gói thứ 4 trở đi là quá trình giao tiếp thật sự giữa client và server.

*(Chèn ảnh: các filter DNS/HTTP/tcp.flags.syn trên Wireshark, và cửa sổ Follow TCP Stream)*

### Lab 1.3 — Tra cứu DNS thủ công

Trên **Windows**, dùng `nslookup`:

```
nslookup google.com
nslookup -type=MX google.com
nslookup -type=TXT google.com
```

Kết quả cho thấy IP của `google.com`, mail exchanger (`smtp.google.com` với MX preference = 10), và loạt TXT record dùng để xác thực domain (Google site verification, Facebook domain verification, Docusign, Apple domain verification...).

Trên **Linux**, dùng `dig`:

```bash
dig google.com
dig google.com MX
```

Kết quả tương tự nslookup nhưng hiển thị chi tiết hơn: query time, server trả lời, TTL...

Quay lại Wireshark để đối chiếu gói tin DNS thực tế:

- Các gói tin DNS chứa record **A, AAAA, PTR**. Có domain không phân giải được do không tồn tại (`Non-existent domain`).
- Tìm gói **query** — cột Info có dạng `Standard query 0x.... A google.com`.
- Tìm gói **response** tương ứng — cột Info có dạng `Standard query response 0x.... A google.com A <IP>`.
- So sánh **Transaction ID** giữa query và response (phải trùng nhau) — đây là cách phân biệt cặp query/response khi có nhiều truy vấn diễn ra cùng lúc.
- Quan sát thêm: gói query dùng **port đích 53**, gói response trả về từ **port nguồn 53**.

*(Chèn ảnh: nslookup/dig trên terminal, và các gói DNS query/response trên Wireshark)*

### Lab 1.4 — Kiểm tra port và dịch vụ đang chạy

Trên **Windows**:

```
netstat -ano
```

Liệt kê toàn bộ port cùng trạng thái (`LISTENING`, `ESTABLISHED`, `CLOSE_WAIT`...) kèm PID tương ứng. Đối chiếu PID với **Task Manager → Details** để biết process nào đang mở port nào.

Trên **Linux**:

```bash
sudo ss -tulnp
```

Trong đó: `t` = TCP, `u` = UDP, `l` = listening, `n` = hiển thị dạng numeric, `p` = hiện tên process đi kèm port.

Cuối cùng, dùng **Nmap** quét từ máy Windows sang máy Linux để xác nhận lại từ góc nhìn bên ngoài:

```
nmap -sV 192.168.1.145
```

Kết quả: port 22 (SSH — OpenSSH 8.9p1 Ubuntu), port 80 (HTTP — nginx 1.18.0), port 443 (SSL/HTTP — Elasticsearch Kibana). Tùy chọn `-sV` giúp liệt kê luôn version của service đang chạy trên từng cổng, rất hữu ích khi cần đánh giá bề mặt tấn công (attack surface) của một host.

*(Chèn ảnh: netstat -ano, Task Manager, ss -tulnp, và kết quả nmap -sV)*

---

Tuần 1 tạm dừng ở đây — nắm được OSI, TCP/UDP, port/socket, DNS, NAT, DHCP và vài khái niệm bảo mật nền tảng là đủ vốn liếng để bước sang các phần sâu hơn. Ae nào có góp ý hay thấy chỗ nào note nhầm thì để lại comment nhé!

Peace!
