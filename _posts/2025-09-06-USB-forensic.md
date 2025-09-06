---
title: "USB Mass Storage over PCAP"
date: 2025-09-06 10:00:00 +0700
categories: [ctf]
tags: [forensic, ctf, wireshark]
---

# USB Mass Storage over PCAP

Chào ae nhé. Hôm nay nghịch vòng quanh CTF thì gặp một dạng bài khá thú vị: **USB truyền file qua PCAP**.  
Nghe thì lạ nhưng thực ra cũng dễ hiểu thôi, mình note lại ở đây để ae tiện theo dõi.

## 1. USB Mass Storage trong Wireshark là gì?

Khi ae copy dữ liệu từ máy sang USB, **toàn bộ dữ liệu** đều bị ghi lại trong PCAP.  
Nhưng **không phải raw file** như khi export object HTTP, mà dữ liệu sẽ bị chia thành nhiều block nhỏ (do USB driver quản lý), sau đó đóng gói và truyền đi qua cổng USB.  

Kết quả: Wireshark sẽ bắt được **hàng loạt packet** (có thể từ vài chục đến hàng nghìn, tuỳ kích thước file).

## 2. Bài toán trong CTF

Vậy nhiệm vụ của ae là gì ? Ae đi tìm vị trí dữ liệu bắt đầu bị đóng gói -> export hết sạch đống gói tin đấy ra -> ghép lại -> rồi làm gì đó thêm nữa để khôi phục 

Nhiệm vụ cơ bản:

1. Tìm vị trí bắt đầu dữ liệu được ghi (SCSI: Data Out).  
2. Export toàn bộ packet chứa payload.  
3. Ghép lại thành binary.  
4. Tìm magic bytes → reconstruct file.  

## 3. Ví dụ: Nullcon HackIM CTF Berlin 2025

### a. Mở file PCAP

<img width="505" height="443" alt="image" src="https://github.com/user-attachments/assets/c48ca180-cf8a-485f-93a1-9e8588f31fc4">

Mở bằng Wireshark, thấy ngay nhiều giao thức USB:  

<img width="1622" height="445" alt="image" src="https://github.com/user-attachments/assets/8d8b6ce6-a55f-4024-97ca-6f72efbe95da">

### b. Phát hiện file bị copy
Trong packet `607` có string **flag.tar.gz**, nhưng đó chỉ là tên file, **không chứa data**: 

<img width="1529" height="277" alt="image" src="https://github.com/user-attachments/assets/c63972b8-03a5-4cf1-8c1d-0aae27b82b73">

Cái packet đấy chỉ chứa tên file được truyền đi thôi, còn data thật sẽ nằm ở **SCSI: Data Out** (data bị truyền đi). Okay, đáp cái filter cho cá mập lọc hết đống packet Data out đấy ra rồi export hết sạch sành sanh nó ra thành 1 file pcap mới. 
Mình đã biết nó là file **.gz** rồi nhỉ, thế thì chỉ cần đi tìm đoạn data nào chứa header magic bytes của **.gz** rồi export là được. Code python đây: 
### c. Export bằng Python
```python
from scapy.all import rdpcap, Raw

packets = rdpcap("usbstorage.pcapng")
data = b"".join(bytes(p[Raw]) for p in packets if Raw in p)

magic = b"\x1f\x8b\x08"  # Gzip header
idx = data.find(magic)

if idx == -1:
    print("Không tìm thấy gzip header!")
else:
    with open("flag.tar.gz", "wb") as f:
        f.write(data[idx:])
    print("Đã xuất flag.tar.gz, thử tar -xvzf flag.tar.gz")
```
Giải nén flag.tar.gz ra → có flag.
> Flag: ENO{USB_STORAGE_SHOW_ME_THE_FLAG_PLS}

Thật ra thì cái dạng này cũng không quá khó hiểu. 
Giải thích chi tiết hơn về cách làm việc của USB thì mình sẽ nhờ ChatGPT giải thích ngắn gọn ở bên dưới nhé ae ! Học được cái gì mới mới là lên blog để lưu lại ngay hehe.

## 4. Giải thích kỹ hơn (ChatGPT summary)

### USB Mass Storage (USBMS)

- Là lớp giao thức cho phép USB flash/ổ cứng ngoài giao tiếp như một **block device**.  
- Sử dụng **Bulk-Only Transport (BOT)** với lệnh **SCSI** (Read, Write, Inquiry...).

### Các thành phần

- **CBW (Command Block Wrapper):** host gửi lệnh.  
- **Data phase:**  
  - **Data-Out:** host → USB.  
  - **Data-In:** USB → host.  
- **CSW (Command Status Wrapper):** USB trả kết quả.

### PCAP & Forensic

- Khi copy file, sinh ra nhiều lệnh **Write(10)** với payload chứa data file.  
- Forensic thường làm theo quy trình:
  1. Extract `usb.capdata`.  
  2. Ghép nối đúng thứ tự.  
  3. Tìm **magic bytes** (ZIP, PNG, GZ...).  
  4. Dump thành file gốc.  

### Công cụ

- **Wireshark:** filter `usb.capdata`, save raw.  
- **Tshark:**
  ```bash
  tshark -r usb.pcapng -Y "usb.capdata" -T fields -e usb.capdata > out.hex
  xxd -r -p out.hex > out.bin
  ```

### Ý nghĩa trong CTF
Ngay cả khi file đã bị xoá khỏi USB, PCAP vẫn chứa toàn bộ dữ liệu lúc ghi ban đầu → dễ dàng khôi phục flag.
Đây là lý do dạng forensic này rất hay xuất hiện trong các bài CTF.  

Peace!
