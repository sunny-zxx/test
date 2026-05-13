import os
import time
import json
import requests
from datetime import datetime, timedelta
from selenium import webdriver
from selenium.webdriver.edge.options import Options

# ================= 配置区域 =================
# 你的 Edge 用户数据路径
USER_DATA_DIR = r"C:\Users\liusaibo\AppData\Local\Microsoft\Edge\User Data"
PROFILE_DIR = "Profile 4" 

# 飞书后台页面（用于获取 Token）
Page_URL = "https://zaglobal.feishu.cn/admin/security/data-classification/discovery?tab=log"
# 飞书数据接口 API
API_URL = "https://zaglobal.feishu.cn/suite/admin/data_discovery/event/list"
# ===========================================

driver = None
def get_tokens_from_browser():
    """使用 Selenium 打开浏览器并提取 Cookies 和 CSRF Token"""
    print(">>> [Step 1] 正在初始化浏览器以获取凭证...")
    
    # 1. 清理旧进程
    os.system("taskkill /im msedge.exe /f >nul 2>&1")
    time.sleep(2) 

    # 2. 配置 Edge
    edge_options = Options()
    edge_options.add_argument(f"user-data-dir={USER_DATA_DIR}")
    edge_options.add_argument(f"profile-directory={PROFILE_DIR}")
    edge_options.add_experimental_option("detach", True)
    edge_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    edge_options.add_argument("--disable-blink-features=AutomationControlled")

    try:
        driver = webdriver.Edge(options=edge_options)
        
        # 3. 跳转页面加载环境
        print(f"正在打开页面: {Page_URL}")
        driver.get(Page_URL)
        
        print("等待页面加载 (10秒)...")
        time.sleep(10) 

        # 4. 提取 Cookies
        selenium_cookies = driver.get_cookies()
        cookie_dict = {}
        for cookie in selenium_cookies:
            cookie_dict[cookie['name']] = cookie['value']
        
        # 5. 提取 CSRF Token (飞书接口强制要求)
        x_csrf_token = cookie_dict.get("csrf_token")
        if not x_csrf_token:
            x_csrf_token = cookie_dict.get("_csrf_token")
        
        if not x_csrf_token:
            raise ValueError("❌ 未能在 Cookie 中找到 csrf_token，请检查是否已登录！")

        print(f"✅ 成功获取凭证！")
        print(f"   CSRF Token: {x_csrf_token}")
        print(f"   Cookie 数量: {len(cookie_dict)}")
        
        return cookie_dict, x_csrf_token

    except Exception as e:
        print(f"❌ 浏览器操作失败: {e}")
        return None, None
    finally:
        if driver:
            # 获取完 Token 后可以关闭浏览器，也可以保留
            # driver.quit() 
            pass

def fetch_data_loop(cookie_dict, x_csrf_token):
    """使用 requests 循环拉取所有数据"""
    print("\n>>> [Step 2] 开始通过 API 抓取数据...")

    # 1. 计算时间范围 (当前时间往前推7天)
    now = datetime.now()
    seven_days_ago = now - timedelta(days=7)
    
    # 转换为毫秒级时间戳
    end_scan_time = int(now.timestamp() * 1000)
    start_scan_time = int(seven_days_ago.timestamp() * 1000)

    print(f"   时间范围: {seven_days_ago.strftime('%Y-%m-%d')} ({start_scan_time}) -> {now.strftime('%Y-%m-%d')} ({end_scan_time})")

    # 2. 构造基础请求头
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Content-Type": "application/json;charset=UTF-8",
        "Accept": "application/json, text/plain, */*",
        "Referer": Page_URL,
        "Origin": "https://zaglobal.feishu.cn",
        "X-Csrf-Token": x_csrf_token,  # 【关键】
        "X-Requested-With": "XMLHttpRequest"
    }

    all_events = []
    page_token = ""
    has_more = True
    page_count = 0

    while has_more:
        page_count += 1
        print(f"   正在请求第 {page_count} 页 (PageToken: {page_token[:10]}...)...", end="")

        payload = {
            "filter": {
                "startScanTime": str(start_scan_time),
                "endScanTime": str(end_scan_time)
            },
            "pageSize": 20,
            "pageToken": page_token
        }

        try:
            # 发送请求 (requests 会自动处理 cookie_dict)
            response = requests.post(API_URL, headers=headers, cookies=cookie_dict, json=payload)
            
            if response.status_code != 200:
                print(f"\n❌ 请求失败，状态码: {response.status_code}")
                print(response.text)
                break

            resp_json = response.json()
            
            # 检查业务状态码
            if resp_json.get("code") != 0:
                print(f"\n❌ 业务报错: {resp_json}")
                break

            data = resp_json.get("data", {})
            events = data.get("events", [])
            
            # 收集数据
            all_events.extend(events)
            print(f" 获取到 {len(events)} 条数据。")

            # 更新分页状态
            has_more = data.get("HasMore", False)
            page_token = data.get("PageToken", "")

            # 如果没有更多数据，跳出循环
            if not has_more:
                print("   ✅ 所有页面抓取完毕。")
                break
            
            # 稍微等待一下，避免请求过快
            time.sleep(1)

        except Exception as e:
            print(f"\n❌ 请求发生异常: {e}")
            break

    return all_events

#UPLOAD_URL = "https://deep.in.za/deep/feishu/sensitive/upload"
UPLOAD_URL = "https://siem-tools.in.za/deep/api-dev/feishu/sensitive/upload"
BATCH_SIZE = 100
def extract_record(raw_item):
    """
    从原始 JSON 中提取指定字段
    """
    user_name = raw_item.get("entityOwner", {}).get("userName", "")
    hit_rules = raw_item.get("hitRuleList", [])
    rule_names = [r.get("displayRuleName", "") for r in hit_rules if r.get("displayRuleName")]
    display_rule_name_str = ",".join(rule_names)

    return {
        "docType": raw_item.get("docType"),
        "entityName": raw_item.get("entityName"),
        "userName": user_name,
        "displayRuleName": display_rule_name_str,
        "isExternalSharing": raw_item.get("isExternalSharing"),
        "policyName": raw_item.get("policyName"),
        "scanTime": raw_item.get("scanTime")
    }

def upload_to_server(data_list):
    
    """
    分批上传数据到服务器
    """
    if not data_list:
        return

    total_count = len(data_list)
    print(f"[*] 准备处理 {total_count} 条数据并上传...")

    # 1. 数据清洗/格式化
    cleaned_data = []
    for item in data_list:
        cleaned_data.append(extract_record(item))

    # 2. 分批次 POST 上传
    headers = {
        "Content-Type": "application/json"
    }

    # range(start, stop, step) 实现分批
    for i in range(0, total_count, BATCH_SIZE):
        batch = cleaned_data[i : i + BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        try:
            # 发送请求
            resp = requests.post(UPLOAD_URL, json=batch, headers=headers,verify=False)
            if resp.status_code == 200:
                print(f"   [Batch {batch_num}] 成功上传 {len(batch)} 条")
            else:
                print(f"   [Batch {batch_num}] 上传失败. HTTP {resp.status_code}: {resp.text}")
        except Exception as e:
            print(f"   [Batch {batch_num}] 请求异常: {e}")

def main():
    # 1. 获取 Token
    cookies, csrf_token = get_tokens_from_browser()
    if not cookies or not csrf_token:
        print("程序终止：无法获取有效凭证。")
        return
    # 2. 循环抓取数据
    all_data = fetch_data_loop(cookies, csrf_token)

    # 关闭浏览器
    if driver:
        driver.quit()
    # 3. 保存结果
    if all_data:
        filename = f"./feishu/log/feishu_scan_data_{datetime.now().strftime('%Y%m%d')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(all_data, f, ensure_ascii=False, indent=2)
        
        print(f"\n>>> [Step 3] 结果已保存！")
        print(f"   文件名: {filename}")
        print(f"   总数据量: {len(all_data)} 条")
    else:
        print("\n>>> 未抓取到任何数据。")

    # 4. 上传至服务器 https://deep.in.za
    upload_to_server(all_data)

if __name__ == "__main__":
    main()
