"""天翼云自动签到脚本
支持环境变量配置和GitHub Actions运行
"""
import time
import re
import json
import base64
import hashlib
import urllib.parse
import rsa
import requests
import random
import os
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
B64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

s = requests.Session()

# 从环境变量获取配置
username = os.getenv('TYY_USERNAME')
password = os.getenv('TYY_PASSWORD')
pushplus_token = os.getenv('PUSHPLUS_TOKEN', '')  # pushplus推送token

# 如果环境变量未设置，尝试使用交互式输入（本地调试用）
if not username or not password:
    if os.getenv('GITHUB_ACTIONS'):
        raise ValueError("在GitHub Actions中运行时必须设置TYY_USERNAME和TYY_PASSWORD环境变量")
    username = input("账号：")
    password = input("密码：")

assert username and password, "请提供有效的账号和密码"

if not pushplus_token:
    logger.warning("未设置PUSHPLUS_TOKEN环境变量，签到结果将不会推送通知")


def int2char(a):
    return BI_RM[a]


def b64tohex(a):
    d = ""
    e = 0
    c = 0
    for i in range(len(a)):
        if list(a)[i] != "=":
            v = B64MAP.index(list(a)[i])
            if 0 == e:
                e = 1
                d += int2char(v >> 2)
                c = 3 & v
            elif 1 == e:
                e = 2
                d += int2char(c << 2 | v >> 4)
                c = 15 & v
            elif 2 == e:
                e = 3
                d += int2char(c)
                d += int2char(v >> 2)
                c = 3 & v
            else:
                e = 0
                d += int2char(c << 2 | v >> 4)
                d += int2char(15 & v)
    if e == 1:
        d += int2char(c << 2)
    return d


def rsa_encode(j_rsakey, string):
    rsa_key = f"-----BEGIN PUBLIC KEY-----\n{j_rsakey}\n-----END PUBLIC KEY-----"
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
    result = b64tohex((base64.b64encode(rsa.encrypt(f'{string}'.encode(), pubkey))).decode())
    return result


def calculate_md5_sign(params):
    return hashlib.md5('&'.join(sorted(params.split('&'))).encode('utf-8')).hexdigest()


def login(username, password):
    # https://m.cloud.189.cn/login2014.jsp?redirectURL=https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html
    url = ""
    urlToken = "https://m.cloud.189.cn/udb/udb_login.jsp?pageId=1&pageKey=default&clientType=wap&redirectURL=https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html"
    s = requests.Session()
    r = s.get(urlToken)
    pattern = r"https?://[^\s'\"]+"  # 匹配以http或https开头的url
    match = re.search(pattern, r.text)  # 在文本中搜索匹配
    if match:  # 如果找到匹配
        url = match.group()  # 获取匹配的字符串
        # print(url)  # 打印url
    else:  # 如果没有找到匹配
        print("没有找到url")

    r = s.get(url)
    # print(r.text)
    pattern = r"<a id=\"j-tab-login-link\"[^>]*href=\"([^\"]+)\""  # 匹配id为j-tab-login-link的a标签，并捕获href引号内的内容
    match = re.search(pattern, r.text)  # 在文本中搜索匹配
    if match:  # 如果找到匹配
        href = match.group(1)  # 获取捕获的内容
        # print("href:" + href)  # 打印href链接
    else:  # 如果没有找到匹配
        print("没有找到href链接")

    r = s.get(href)
    captchaToken = re.findall(r"captchaToken' value='(.+?)'", r.text)[0]
    lt = re.findall(r'lt = "(.+?)"', r.text)[0]
    returnUrl = re.findall(r"returnUrl= '(.+?)'", r.text)[0]
    paramId = re.findall(r'paramId = "(.+?)"', r.text)[0]
    j_rsakey = re.findall(r'j_rsaKey" value="(\S+)"', r.text, re.M)[0]
    s.headers.update({"lt": lt})

    username = rsa_encode(j_rsakey, username)
    password = rsa_encode(j_rsakey, password)
    url = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
        'Referer': 'https://open.e.189.cn/',
    }
    data = {
        "appKey": "cloud",
        "accountType": '01',
        "userName": f"{{RSA}}{username}",
        "password": f"{{RSA}}{password}",
        "validateCode": "",
        "captchaToken": captchaToken,
        "returnUrl": returnUrl,
        "mailSuffix": "@189.cn",
        "paramId": paramId
    }
    r = s.post(url, data=data, headers=headers, timeout=5)
    if (r.json()['result'] == 0):
        print(r.json()['msg'])
    else:
        print(r.json()['msg'])
    redirect_url = r.json()['toUrl']
    r = s.get(redirect_url)
    return s


def main():
    try:
        logger.info("开始天翼云签到流程")
        s = login(username, password)
        if not s:
            logger.error("登录失败")
            return
            
        rand = str(round(time.time() * 1000))
        surl = f'https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K'
        url = f'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN'
        url2 = f'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN'
        url3 = f'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_2022_FLDFS_KJ&activityId=ACT_SIGNIN'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
            "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
            "Host": "m.cloud.189.cn",
            "Accept-Encoding": "gzip, deflate",
        }
        
        try:
            response = s.get(surl, headers=headers, timeout=20)
            response.raise_for_status()
            netdiskBonus = response.json()['netdiskBonus']
            
            if (response.json()['isSign'] == "false"):
                logger.info(f"未签到，签到获得{netdiskBonus}M空间")
                res1 = f"未签到，签到获得{netdiskBonus}M空间"
            else:
                logger.info(f"已经签到过了，签到获得{netdiskBonus}M空间")
                res1 = f"已经签到过了，签到获得{netdiskBonus}M空间"
        except Exception as e:
            logger.error(f"签到失败: {str(e)}")
            res1 = "签到异常"
            
        # 抽奖部分
        res2 = res3 = res4 = ""
        try:
            response = s.get(url, headers=headers, timeout=20)
            response.raise_for_status()
            if ("errorCode" in response.text):
                logger.warning(f"抽奖1失败: {response.text}")
            else:
                description = response.json()['description']
                logger.info(f"抽奖1获得{description}")
                res2 = f"抽奖1获得{description}"
        except Exception as e:
            logger.error(f"抽奖1异常: {str(e)}")
            
        try:
            response = s.get(url2, headers=headers, timeout=20)
            response.raise_for_status()
            if ("errorCode" in response.text):
                logger.warning(f"抽奖2失败: {response.text}")
            else:
                description = response.json()['description']
                logger.info(f"抽奖2获得{description}")
                res3 = f"抽奖2获得{description}"
        except Exception as e:
            logger.error(f"抽奖2异常: {str(e)}")
            
        try:
            response = s.get(url3, headers=headers, timeout=20)
            response.raise_for_status()
            if ("errorCode" in response.text):
                logger.warning(f"抽奖3失败: {response.text}")
            else:
                description = response.json()['description']
                logger.info(f"抽奖3获得{description}")
                res4 = f"抽奖3获得{description}"
        except Exception as e:
            logger.error(f"抽奖3异常: {str(e)}")

        # 发送pushplus通知
        if pushplus_token:
            try:
                title = '天翼云盘签到'
                url = 'http://www.pushplus.plus/send'
                data = {
                    "token": pushplus_token,
                    "title": title,
                    "content": f'账号: {username}\n{res1}\n{res2}\n{res3}\n{res4}',
                    "template": "html"
                }
                headers = {'Content-Type': 'application/json'}
                response = requests.post(url, json=data, headers=headers, timeout=15)
                response.raise_for_status()
                
                if response.json()['code'] == 200:
                    logger.info("pushplus通知发送成功")
                else:
                    logger.warning(f"pushplus通知发送失败: {response.json()}")
            except Exception as e:
                logger.error(f"发送pushplus通知异常: {str(e)}")
                
    except Exception as e:
        logger.error(f"程序运行出现异常: {str(e)}")
        raise


def lambda_handler(event, context):
    try:
        main()
        return {"statusCode": 200, "body": "Success"}
    except Exception as e:
        logger.error(f"AWS Lambda运行异常: {str(e)}")
        return {"statusCode": 500, "body": str(e)}


def main_handler(event, context):
    try:
        main()
        return {"code": 0, "message": "Success"}
    except Exception as e:
        logger.error(f"腾讯云函数运行异常: {str(e)}")
        return {"code": -1, "message": str(e)}


def handler(event, context):
    try:
        main()
        return {"success": True}
    except Exception as e:
        logger.error(f"阿里云函数运行异常: {str(e)}")
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    # time.sleep(random.randint(5, 30))
    main()
