import requests, urllib3, json, os, re, sys
from pyperclip import copy as copy
from pprint import pprint

urllib3.disable_warnings()

headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"}

login_info = {
    "account_type":"not_social",
    "email":"INPUT",
    "pw":"INPUT"
}

login_a = "https://www.criminalip.io/ko/login?h2=%2F"
login_b = "https://www.criminalip.io/api/auth/user/login"
login_c = "https://www.criminalip.io/mypage/information"
mypage = "https://www.criminalip.io/api/proxy/auth/mypage/getMyInfo"

def check_sits(host):
    response = os.system("ping -n 1 " + host)
    if response == 0:
        result = "[+] Status :: Open\n\n"
    else:
        result = "[-] Status :: Close\n\n"
    return result

with requests.Session() as res:
    URL_Content = res.get(login_a, headers=headers, verify=False).content
    URL_Content = res.post(login_b, data=login_info, headers=headers, verify=False).content

    if 'csrf_access_token' in res.post(login_b, data=login_info, headers=headers, verify=False).cookies:
        csrftoken=res.post(login_b, data=login_info, headers=headers, verify=False).cookies['csrf_access_token']

    login_info = {"csrf_access_token":csrftoken}

    pprint("CSRF Token: " + csrftoken + "\n\n")

    headers["referer"]=login_c; headers["x-csrf-token"]=csrftoken
    
    URL_Content = res.get(login_c, headers=headers, verify=False).content   

    result = res.get(mypage, headers=headers, verify=False).text
    
    #API Key 사용
    headers["x-api-key"] = "API_KEY_INPUT";

    os.system('cls')

    select_number = input("1 - IP Search\n2 - Banner Search\n3 - Domain Search\n\nSelect Number : ")
    if select_number == "1":
        ip = input("Input IP : ")

        ip_data = "https://api.criminalip.io/v1/ip/data?ip="
        URL_Content = res.get(ip_data+ip+"&full=true", headers=headers, verify=False).content
        pprint("IP Data API : " + str(json.dumps(json.loads(URL_Content), indent=4, ensure_ascii=False)))

        ip_summary = "https://api.criminalip.io/v1/ip/summary?ip="
        URL_Content = res.get(ip_summary+ip, headers=headers, verify=False).content
        pprint("\n\nIP Summary API : " + str(json.dumps(json.loads(URL_Content), indent=4, ensure_ascii=False)))

        ip_vpn = "https://api.criminalip.io/v1/ip/vpn?ip="
        URL_Content = res.get(ip_vpn+ip, headers=headers, verify=False).content
        pprint("\n\nIP VPN API : " + str(json.dumps(json.loads(URL_Content), indent=4, ensure_ascii=False)))

        ip_hosting = "https://api.criminalip.io/v1/ip/hosting?ip="
        URL_Content = res.get(ip_hosting+ip, headers=headers, verify=False).content
        pprint("\n\nIP hosting API : " + str(json.dumps(json.loads(URL_Content), indent=4, ensure_ascii=False)))
    elif select_number == "2":
        query = input("Banner Input Query : ")
        banner_search = "https://api.criminalip.io/v1/banner/search?query="
        URL_Content = res.get(banner_search+query+"&offset=0", headers=headers, verify=False).content
        pprint("Banner Search API : " + str(json.dumps(json.loads(URL_Content), indent=4, ensure_ascii=False)))

        banner_stats = "https://api.criminalip.io/v1/banner/stats?query="
        URL_Content = res.get(banner_stats+query, headers=headers, verify=False).content
        pprint("Banner Stats API : " + str(json.dumps(json.loads(URL_Content), indent=4, ensure_ascii=False)))

# 특이사항으로 Domain 제한이 있음(일반 계정 - 도메인 검색 로직이 미흡하여 일회용 계정을 통해 생성이 가능하니 이 부분을 이용하면 됨)
    elif select_number == "3":
        os.system('cls')
        select = input("1. Domain Search(Scan)\n2. Domain Status(Scan Result)\n3. Domain Report(iframe, hidden_element, js obfuscate) + Technologies\n4. Domain Search Report Result\n\nSelect input: ")
        if select == "1":
            domain = input("Domain Input : ")
            check_sits(domain) # status code print
            domain_scan = "https://api.criminalip.io/v1/domain/scan"
            data = {"query":domain}
            URL_Content = res.post(domain_scan, data=data, headers=headers, verify=False).content
            URL_Content = str(URL_Content.decode())
            print("[Domain Report id] : " + "".join(re.findall("scan\_id\"\:(\d*)\}",URL_Content)))
            print("The domain report id value has been copied automatically, so please run it again and paste it through option 2 and check the report by looking at the status.")
            copy("".join(re.findall("scan\_id\"\:(\d*)\}",URL_Content)))
        elif select == "2":
            domain = input("Report Number Input : ")
            domain_scan = "https://api.criminalip.io/v1/domain/status/"
            domain_scan = domain_scan + str(domain)
            URL_Content = res.get(domain_scan, headers=headers, verify=False).content
            URL_Content = str(URL_Content.decode())
            if "".join(re.findall("scan\_percentage\"\:(.+?)\,",URL_Content)) in "-2":
                os.system('cls')
                print("[Error] Domain does not exist")
            elif "".join(re.findall("scan\_percentage\"\:(.+?)\,",URL_Content)) in "-1":
                os.system('cls')
                print("[Error] Scan failed")
            elif "".join(re.findall("scan\_percentage\"\:(.+?)\}",URL_Content)) in "100":
                os.system('cls')
                print("[Success] OK!")
                select = input("The report has been generated, do you want to check it?\n\n1. Yes\n2. No\n\nSelect : ")
                if select == "1":
                    os.system('cls')
                    domain_reports_id = "https://api.criminalip.io/v1/domain/report/"
                    domain_reports_id = domain_reports_id + domain
                    URL_Content = res.get(domain_reports_id, headers=headers, verify=False).content
                    try:
                        # print("[+] Score : " + json.loads(URL_Content)['data']['main_domain_info']['domain_score']['score'])
                        for Result in json.loads(URL_Content)['data']['network_logs']:
                            if "".join(re.findall(".*\.js","".join(Result['url']))):
                                print("[+] Javascript : " + "".join(re.findall(".*\.js","".join(Result['url']))))
                        print("\n\n")
                        for Result in json.loads(URL_Content)['data']['technologies']:
                            print("[+] Category : " + "".join(Result['categories']))
                            print("[+] Name : "     + Result['name'])
                            print("[+] Version : "  , Result['version'])
                            print("[+] Vulner : "   + ", ".join(Result['vulner']) + "\n")
                    except Exception:
                        print("I don't think the result has come out yet!\n\nPlease try again!")
                else:
                    sys.exit()
            else:
                os.system('cls')
                print("[Error] API Error!")
        
        elif select == "3":
            os.system('cls')
            domain = input("Domain URL Input : ")
            domain_reports = "https://api.criminalip.io/v1/domain/reports?query="
            URL_Content = res.get(domain_reports+domain, headers=headers, verify=False).content
            
            for Data in json.loads(URL_Content.decode())['data'].values():
                for Value in Data:
                    print("[ Scan ID ] : " + str(Value['scan_id']))
                    print("[ URL ] : "     + str(Value['url']))
                    print("[ Title ] : "   + str(Value['title']))
                    print("[ Issues ] : "  + str(Value['issues']))
                    print("[ Score ] : "   + str(Value['score']))
                    print("\n")
        
        elif select == "4":
            domain = input("Report ID Input : ")
            domain_reports_id = "https://api.criminalip.io/v1/domain/report/"
            domain_reports_id = domain_reports_id + domain
            URL_Content = res.get(domain_reports_id, headers=headers, verify=False).content
            pprint("\n\nDomain Reports API Result : " + str(json.dumps(json.loads(URL_Content), indent=4, ensure_ascii=False)))
            print("[+] Score : " + json.loads(URL_Content)['data']['main_domain_info']['domain_score']['score'])
            
        else:
            print("Number Error")

    else:
        pprint("[-] Don't Technology ..")
