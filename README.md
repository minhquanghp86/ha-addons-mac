# Darboard Add-ons

Repo add-on riêng tư cho Home Assistant.

## Cài
1. Settings → Add-ons → Add-on Store → ⋮ → Repositories
2. Thêm: `https://github.com/minhquanghp86/ha-addons-mac`
   (repo private: cần Personal Access Token — dùng URL
   `https://<user>:<PAT>@github.com/minhquanghp86/ha-addons-mac`)
3. Cài **ESP MAC Reader**, đặt `password` trong Configuration.

## Add-on
### ESP MAC Reader (esptool_mac)
- Trang web (cổng 8900) có đăng nhập.
- Khách cắm ESP32 vào **máy của họ**; `esptool-js` chạy trong trình duyệt đọc MAC eFuse (không ghi gì vào chip).
- Sau khi đọc, khách điền tên/mã đơn và bấm gửi → lưu `/data/macs.jsonl`, tuỳ chọn gửi Telegram.
- Yêu cầu: Chrome/Edge trên máy tính (Web Serial).
