"""
cron: 0 */6 * * *
new Env("Linux.Do 签到")
"""

import os
import random
import time
import functools
import sys
import re
from loguru import logger
from DrissionPage import ChromiumOptions, Chromium
from tabulate import tabulate
from curl_cffi import requests
from bs4 import BeautifulSoup


def retry_decorator(retries=3, min_delay=5, max_delay=10):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == retries - 1:  # 最后一次尝试
                        logger.error(f"函数 {func.__name__} 最终执行失败: {str(e)}")
                    logger.warning(
                        f"函数 {func.__name__} 第 {attempt + 1}/{retries} 次尝试失败: {str(e)}"
                    )
                    if attempt < retries - 1:
                        sleep_s = random.uniform(min_delay, max_delay)
                        logger.info(
                            f"将在 {sleep_s:.2f}s 后重试 ({min_delay}-{max_delay}s 随机延迟)"
                        )
                        time.sleep(sleep_s)
            return None

        return wrapper

    return decorator


os.environ.pop("DISPLAY", None)
os.environ.pop("DYLD_LIBRARY_PATH", None)

USERNAME = os.environ.get("LINUXDO_USERNAME")
PASSWORD = os.environ.get("LINUXDO_PASSWORD")
BROWSE_ENABLED = os.environ.get("BROWSE_ENABLED", "true").strip().lower() not in [
    "false",
    "0",
    "off",
]
if not USERNAME:
    USERNAME = os.environ.get("USERNAME")
if not PASSWORD:
    PASSWORD = os.environ.get("PASSWORD")
GOTIFY_URL = os.environ.get("GOTIFY_URL")
GOTIFY_TOKEN = os.environ.get("GOTIFY_TOKEN")
SC3_PUSH_KEY = os.environ.get("SC3_PUSH_KEY")
WXPUSH_URL = os.environ.get("WXPUSH_URL")
WXPUSH_TOKEN = os.environ.get("WXPUSH_TOKEN")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_USERID = os.environ.get("TELEGRAM_USERID")

HOME_URL = "https://linux.do/"
LATEST_URL = "https://linux.do/latest"
LOGIN_URL = "https://linux.do/login"
SESSION_URL = "https://linux.do/session"
CSRF_URL = "https://linux.do/session/csrf"
CONNECT_URL = "https://connect.linux.do/"


class LinuxDoBrowser:
    def __init__(self) -> None:
        from sys import platform

        if platform == "linux" or platform == "linux2":
            platformIdentifier = "X11; Linux x86_64"
        elif platform == "darwin":
            platformIdentifier = "Macintosh; Intel Mac OS X 10_15_7"
        elif platform == "win32":
            platformIdentifier = "Windows NT 10.0; Win64; x64"
        else:
            platformIdentifier = "X11; Linux x86_64"

        co = (
            ChromiumOptions()
            .headless(True)
            .incognito(True)
            .set_argument("--no-sandbox")
        )
        co.set_user_agent(
            f"Mozilla/5.0 ({platformIdentifier}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        )
        self.browser = Chromium(co)
        self.page = self.browser.new_tab()
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Accept-Language": "zh-CN,zh;q=0.9",
            }
        )

        # 统计计数器
        self.browse_count = 0
        self.like_count = 0
        self.read_comments_count = 0

        # 用户信息
        self.display_name = ""
        self.user_id = ""
        self.user_level = 0
        self.next_level = 0
        self.progress_data = []

        # 错误信息
        self.error_message = ""

        # IP 限流状态（与油猴脚本一致）
        self.rate_limited = False
        self.rate_limit_resume_time = 0

    def login(self):
        logger.info("开始登录")
        # Step 1: 用浏览器访问登录页面，从 meta 标签获取 CSRF token
        logger.info("访问登录页面获取 CSRF token...")
        self.page.get(LOGIN_URL)
        time.sleep(3)

        # 检测 429 IP 限流（与油猴脚本一致）
        if self.check_rate_limit(self.page):
            self.error_message = "429 IP 限流，30分钟后恢复"
            logger.error(self.error_message)
            return False

        # 检测 CF 403 错误（与油猴脚本一致）
        if self.check_cf_403_error(self.page):
            logger.warning("登录页面检测到 CF 403 错误，尝试 challenge...")
            if not self.handle_cf_403(self.page, LOGIN_URL):
                self.error_message = "登录页面 CF 403 处理失败"
                logger.error(self.error_message)
                return False

        # 检测 CF 5秒盾
        if self.check_cf_challenge(self.page):
            logger.warning("登录页面触发 CF 验证，等待通过...")
            if not self.wait_cf_challenge(self.page):
                self.error_message = "登录页面 CF 验证失败"
                logger.error(self.error_message)
                return False

        # 从 meta 标签获取 CSRF token
        try:
            csrf_meta = self.page.ele('meta[name="csrf-token"]')
            if csrf_meta:
                csrf_token = csrf_meta.attr('content')
                logger.info(f"CSRF Token obtained: {csrf_token[:10]}...")
            else:
                self.error_message = "未找到 CSRF token meta 标签"
                logger.error(self.error_message)
                return False
        except Exception as e:
            self.error_message = f"获取 CSRF token 失败: {e}"
            logger.error(self.error_message)
            return False

        # Step 2: 使用浏览器提交登录表单
        logger.info("正在登录...")
        try:
            # 填写用户名
            username_input = self.page.ele('#login-account-name')
            if username_input:
                username_input.clear()
                username_input.input(USERNAME)
            else:
                self.error_message = "未找到用户名输入框"
                logger.error(self.error_message)
                return False

            # 填写密码
            password_input = self.page.ele('#login-account-password')
            if password_input:
                password_input.clear()
                password_input.input(PASSWORD)
            else:
                self.error_message = "未找到密码输入框"
                logger.error(self.error_message)
                return False

            # 点击登录按钮
            login_button = self.page.ele('#login-button')
            if login_button:
                login_button.click()
            else:
                self.error_message = "未找到登录按钮"
                logger.error(self.error_message)
                return False

            # 等待登录完成
            time.sleep(5)

            # 检查是否登录成功
            if "login" in self.page.url.lower():
                # 可能还在登录页面，检查错误信息
                error_ele = self.page.ele('.alert-error')
                if error_ele:
                    self.error_message = f"登录失败: {error_ele.text}"
                else:
                    self.error_message = "登录失败，仍在登录页面"
                logger.error(self.error_message)
                return False

            logger.info("登录成功!")

        except Exception as e:
            self.error_message = f"登录异常: {e}"
            logger.error(self.error_message)
            return False

        # 获取连接信息（等级和升级进度）
        self.fetch_connect_info()

        logger.info("导航至首页...")
        self.page.get(HOME_URL)
        time.sleep(3)

        # 验证登录状态
        try:
            user_ele = self.page.ele("@id=current-user")
        except Exception as e:
            logger.warning(f"登录验证异常: {str(e)}")
            return True

        if not user_ele:
            if "avatar" in self.page.html:
                logger.info("登录验证成功 (通过 avatar)")
                return True
            self.error_message = "登录验证失败 (未找到 current-user)"
            logger.error(self.error_message)
            return False
        else:
            logger.info("登录验证成功")
            return True

    def fetch_connect_info(self):
        """获取 connect.linux.do 的用户等级和升级进度"""
        logger.info("获取连接信息...")
        try:
            # 用浏览器访问 connect.linux.do
            self.page.get(CONNECT_URL)
            time.sleep(3)

            html = self.page.html
            soup = BeautifulSoup(html, "html.parser")

            # 解析用户等级: "你好，TC烈火 (lhwd) 2级用户"
            h1 = soup.select_one("h1")
            if h1:
                h1_text = h1.get_text(strip=True)
                # 提取显示名和用户ID
                match = re.search(r"你好，(.+?)\s*\((\w+)\)\s*(\d+)级用户", h1_text)
                if match:
                    self.display_name = match.group(1)
                    self.user_id = match.group(2)
                    self.user_level = int(match.group(3))
                    self.next_level = self.user_level + 1
                    logger.info(f"用户: {self.display_name} ({self.user_id}) {self.user_level}级")

            # 解析升级进度表格
            h2 = soup.select_one("h2")
            if h2:
                h2_text = h2.get_text(strip=True)
                # 提取目标等级: "lhwd - 信任级别 3 的要求"
                match = re.search(r"信任级别\s*(\d+)\s*的要求", h2_text)
                if match:
                    self.next_level = int(match.group(1))

            # 解析表格数据
            rows = soup.select("table tr")
            info = []
            for row in rows:
                cells = row.select("td")
                if len(cells) >= 3:
                    project = cells[0].text.strip()
                    current_cell = cells[1]
                    current = current_cell.text.strip() if current_cell.text.strip() else "0"
                    requirement = cells[2].text.strip() if cells[2].text.strip() else "0"
                    # 检查是否达标 (绿色 = 达标)
                    css_class = current_cell.get("class", [])
                    is_completed = "text-green-500" in css_class if css_class else False
                    info.append({
                        "project": project,
                        "current": current,
                        "requirement": requirement,
                        "completed": is_completed
                    })

            self.progress_data = info

            # 打印表格
            if info:
                print("--------------Connect Info-----------------")
                table_data = [[item["project"], item["current"], item["requirement"]] for item in info]
                print(tabulate(table_data, headers=["项目", "当前", "要求"], tablefmt="pretty"))

        except Exception as e:
            logger.warning(f"获取连接信息异常: {e}")

    def click_topic(self):
        # 导航到最新帖子页面
        logger.info("导航到最新帖子页面...")
        self.page.get(LATEST_URL)
        time.sleep(3)

        # 检测 429 IP 限流（与油猴脚本一致）
        if self.check_rate_limit(self.page):
            self.error_message = "429 IP 限流，30分钟后恢复"
            logger.error(self.error_message)
            return False

        # 检测 CF 403 错误（与油猴脚本一致）
        if self.check_cf_403_error(self.page):
            logger.warning("检测到 CF 403 错误，尝试 challenge...")
            if not self.handle_cf_403(self.page, LATEST_URL):
                self.error_message = "CF 403 处理失败"
                return False

        # 检测 CF 5秒盾
        if self.check_cf_challenge(self.page):
            logger.warning("首页触发 CF 验证，等待通过...")
            if not self.wait_cf_challenge(self.page):
                self.error_message = "无法通过 CF 验证"
                return False

        topic_list = self.page.ele("@id=list-area").eles(".:title")
        if not topic_list:
            self.error_message = "未找到主题帖"
            logger.error(self.error_message)
            return False

        browse_count = min(10, len(topic_list))
        logger.info(f"发现 {len(topic_list)} 个最新帖子，按顺序浏览前 {browse_count} 个")

        # 按顺序浏览（不再随机）
        for i, topic in enumerate(topic_list[:browse_count]):
            # 检查是否被限流（与油猴脚本一致：限流后停止浏览）
            if self.is_rate_limited():
                logger.warning("IP 被限流，停止浏览任务")
                break

            logger.info(f"浏览第 {i + 1}/{browse_count} 个帖子")
            self.click_one_topic(topic.attr("href"))

            # 帖子之间添加随机延迟，避免触发 CF 5秒盾
            if i < browse_count - 1:
                delay = random.uniform(5, 15)
                logger.info(f"等待 {delay:.1f} 秒后浏览下一个帖子...")
                time.sleep(delay)

        return True

    def check_cf_challenge(self, page):
        """检测是否触发 Cloudflare 5秒盾（与油猴脚本一致）"""
        try:
            title = page.title.lower() if page.title else ""
            html = page.html.lower() if page.html else ""
            # 检测 CF 验证页面特征
            cf_indicators = [
                "just a moment" in title,
                "checking your browser" in html,
                "cloudflare" in html and "challenge" in html,
                "cf-browser-verification" in html,
                "_cf_chl" in html
            ]
            return any(cf_indicators)
        except:
            return False

    def check_cf_403_error(self, page):
        """检测 CF 403 错误（与油猴脚本一致）

        油猴脚本检测 .dialog-body 中的 403 error 文本
        """
        try:
            # 检测 .dialog-body 中的错误信息
            dialog_body = page.ele(".dialog-body")
            if dialog_body:
                dialog_text = dialog_body.text.lower()
                if "403" in dialog_text or "error" in dialog_text:
                    logger.warning(f"检测到 CF 403 错误: {dialog_body.text[:100]}")
                    return True
            return False
        except:
            return False

    def check_rate_limit(self, page):
        """检测 429 IP 限流（与油猴脚本一致）

        油猴脚本检测以下关键词：
        - You are being rate limited
        - We have banned you temporarily
        - Too Many Requests
        - Error 429
        - HTTP 429
        """
        try:
            # 先检查是否是正常页面（有 Discourse 特征）
            is_normal_page = (
                page.ele('#main-outlet') or
                page.ele('.topic-list') or
                page.ele('.topic-post') or
                page.ele('.d-header')
            )

            if is_normal_page:
                # 正常页面，清除限流状态
                if self.rate_limited:
                    logger.info("页面恢复正常，清除限流状态")
                    self.rate_limited = False
                    self.rate_limit_resume_time = 0
                return False

            # 检测限流提示文本
            page_text = page.html if page.html else ""
            rate_limit_indicators = [
                "You are being rate limited",
                "We have banned you temporarily",
                "Too Many Requests",
                "Error 429",
                "HTTP 429",
                "rate limited",
                "429"
            ]

            for indicator in rate_limit_indicators:
                if indicator.lower() in page_text.lower():
                    logger.error(f"检测到 429 IP 限流: {indicator}")
                    # 设置 30 分钟后恢复（与油猴脚本一致）
                    self.rate_limited = True
                    self.rate_limit_resume_time = time.time() + (30 * 60)
                    return True

            return False
        except:
            return False

    def is_rate_limited(self):
        """检查是否仍在限流期间"""
        if not self.rate_limited:
            return False

        if time.time() >= self.rate_limit_resume_time:
            logger.info("限流时间已过，恢复正常")
            self.rate_limited = False
            self.rate_limit_resume_time = 0
            return False

        remaining = int((self.rate_limit_resume_time - time.time()) / 60)
        logger.warning(f"仍在限流期间，剩余 {remaining} 分钟")
        return True

    def handle_cf_403(self, page, original_url):
        """处理 CF 403 错误（与油猴脚本一致）

        油猴脚本的处理方式：跳转到 /challenge?redirect=原URL
        """
        try:
            challenge_url = f"https://linux.do/challenge?redirect={original_url}"
            logger.info(f"尝试通过 challenge 页面: {challenge_url}")
            page.get(challenge_url)
            time.sleep(5)

            # 等待 challenge 完成
            if self.wait_cf_challenge(page, timeout=30):
                logger.success("CF 403 challenge 通过")
                return True
            else:
                logger.error("CF 403 challenge 失败")
                return False
        except Exception as e:
            logger.error(f"处理 CF 403 异常: {e}")
            return False

    def wait_cf_challenge(self, page, timeout=30):
        """等待 CF 验证通过"""
        logger.info(f"等待 CF 验证通过（最多 {timeout} 秒）...")
        start_time = time.time()
        while time.time() - start_time < timeout:
            time.sleep(2)
            if not self.check_cf_challenge(page):
                logger.success("CF 验证已通过")
                return True
            logger.info("仍在等待 CF 验证...")
        logger.error("CF 验证超时")
        return False

    @retry_decorator()
    def click_one_topic(self, topic_url):
        # 检查是否在限流期间
        if self.is_rate_limited():
            logger.warning("IP 被限流，跳过此帖子")
            return

        new_page = self.browser.new_tab()
        try:
            new_page.get(topic_url)

            # 检测 429 IP 限流（与油猴脚本一致）
            if self.check_rate_limit(new_page):
                logger.error("触发 429 IP 限流，停止浏览")
                self.error_message = "429 IP 限流，30分钟后恢复"
                return

            # 检测 CF 403 错误（与油猴脚本一致）
            if self.check_cf_403_error(new_page):
                logger.warning("检测到 CF 403 错误，尝试 challenge...")
                if not self.handle_cf_403(new_page, topic_url):
                    logger.error("CF 403 处理失败，跳过此帖子")
                    return

            # 检测 CF 5秒盾
            if self.check_cf_challenge(new_page):
                logger.warning("帖子页面触发 CF 验证，等待通过...")
                if not self.wait_cf_challenge(new_page):
                    logger.error("CF 验证失败，跳过此帖子")
                    return

            self.browse_count += 1
            if random.random() < 0.3:
                self.click_like(new_page)
            self.browse_post(new_page)
        finally:
            try:
                new_page.close()
            except Exception:
                pass

    def browse_post(self, page):
        prev_url = None
        prev_comment_count = 0

        # 获取初始评论数
        try:
            comments = page.eles(".post-stream .topic-post")
            prev_comment_count = len(comments) if comments else 0
        except:
            pass

        # 开始自动滚动，最多滚动10次
        for _ in range(10):
            scroll_distance = random.randint(550, 650)
            logger.info(f"向下滚动 {scroll_distance} 像素...")
            page.run_js(f"window.scrollBy(0, {scroll_distance})")
            logger.info(f"已加载页面: {page.url}")

            # 统计新加载的评论
            try:
                comments = page.eles(".post-stream .topic-post")
                current_comment_count = len(comments) if comments else 0
                new_comments = current_comment_count - prev_comment_count
                if new_comments > 0:
                    self.read_comments_count += new_comments
                    prev_comment_count = current_comment_count
            except:
                pass

            if random.random() < 0.03:
                logger.success("随机退出浏览")
                break

            at_bottom = page.run_js(
                "window.scrollY + window.innerHeight >= document.body.scrollHeight"
            )
            current_url = page.url
            if current_url != prev_url:
                prev_url = current_url
            elif at_bottom and prev_url == current_url:
                logger.success("已到达页面底部，退出浏览")
                break

            wait_time = random.uniform(2, 4)
            logger.info(f"等待 {wait_time:.2f} 秒...")
            time.sleep(wait_time)

    def click_like(self, page):
        try:
            like_button = page.ele(".discourse-reactions-reaction-button")
            if like_button:
                logger.info("找到未点赞的帖子，准备点赞")
                like_button.click()
                self.like_count += 1
                logger.info("点赞成功")
                time.sleep(random.uniform(1, 2))
            else:
                logger.info("帖子可能已经点过赞了")
        except Exception as e:
            logger.error(f"点赞失败: {str(e)}")

    def build_telegram_message(self, success=True):
        """构建 Telegram 通知消息"""
        if success:
            msg = f"✅ <b>LINUX DO 签到成功</b>\n"
            msg += f"👤 {self.display_name} ({self.user_id})\n" if self.display_name else f"👤 {USERNAME}\n"
            msg += "\n"

            # 执行统计
            msg += "📊 <b>执行统计</b>\n"
            msg += f"├ 📖 浏览：{self.browse_count} 篇\n"
            msg += f"├ 💬 阅读评论：{self.read_comments_count} 条\n"
            msg += f"├ 👍 点赞：{self.like_count} 次\n"
            msg += f"├ 📝 发帖：0 篇\n"
            msg += f"└ ✍️ 评论：0 条\n"
            msg += "\n"

            # 当前等级
            if self.user_level > 0:
                msg += f"🏆 <b>当前等级：{self.user_level} 级</b>\n"
            else:
                msg += f"🏆 <b>当前等级：未知</b>\n"
            msg += "\n"

            # 升级进度（仅 2 级及以上用户显示）
            if self.progress_data and self.user_level >= 2:
                msg += f"📈 <b>升级进度 ({self.user_level}→{self.next_level}级)</b>\n"

                # 选择关键指标显示
                key_items = ["访问次数", "回复的话题", "浏览的话题", "已读帖子", "点赞", "获赞"]
                displayed = 0
                completed_count = 0
                total_count = 0

                for item in self.progress_data:
                    project = item["project"]
                    # 跳过"所有时间"和惩罚相关项目
                    if "所有时间" in project or "举报" in project or "禁言" in project or "封禁" in project:
                        continue

                    total_count += 1
                    if item["completed"]:
                        completed_count += 1

                    # 只显示关键指标
                    if any(key in project for key in key_items):
                        icon = "✅" if item["completed"] else "⏳"
                        current = item["current"]
                        requirement = item["requirement"]

                        # 计算差值
                        diff_str = ""
                        if not item["completed"]:
                            try:
                                # 尝试提取数字计算差值
                                curr_num = int(re.search(r"(\d+)", current).group(1))
                                req_num = int(re.search(r"(\d+)", requirement).group(1))
                                if "%" in current:
                                    diff_str = f" (差 {req_num - curr_num}%)"
                                else:
                                    diff_str = f" (差 {req_num - curr_num})"
                            except:
                                pass

                        connector = "├" if displayed < 5 else "└"
                        msg += f"{connector} {icon} {project}：{current} / {requirement}{diff_str}\n"
                        displayed += 1

                msg += "\n"

                # 完成度
                if total_count > 0:
                    percentage = int(completed_count / total_count * 100)
                    filled = completed_count
                    empty = total_count - completed_count
                    progress_bar = "🟩" * filled + "⬜" * empty
                    msg += f"🎯 <b>完成度 {percentage}%</b>\n"
                    msg += f"{progress_bar}\n"
                    msg += f"已完成 {completed_count}/{total_count} 项"
            elif self.user_level == 1:
                msg += "📈 <b>升级进度</b>\n"
                msg += "ℹ️ 1级用户暂无升级进度数据\n"
                msg += "继续活跃即可升级到2级"
        else:
            msg = f"❌ <b>LINUX DO 签到失败</b>\n"
            msg += f"👤 {USERNAME}\n"
            msg += "\n"
            msg += f"⚠️ <b>错误原因</b>\n"
            msg += f"{self.error_message}"

        return msg

    def send_telegram(self, message):
        """发送 Telegram 通知"""
        if not TELEGRAM_TOKEN or not TELEGRAM_USERID:
            logger.info("未配置 Telegram 环境变量，跳过通知发送")
            return

        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
            data = {
                "chat_id": TELEGRAM_USERID,
                "text": message,
                "parse_mode": "HTML"
            }
            response = requests.post(url, data=data, timeout=10)
            if response.status_code == 200:
                logger.success("Telegram 通知发送成功")
            else:
                logger.error(f"Telegram 通知发送失败: {response.text}")
        except Exception as e:
            logger.error(f"Telegram 通知发送异常: {e}")

    def send_notifications(self, success=True):
        """发送所有通知"""
        # Telegram 通知
        tg_message = self.build_telegram_message(success)
        self.send_telegram(tg_message)

        # 简单状态消息（用于其他通知渠道）
        if success:
            status_msg = f"✅每日登录成功: {USERNAME}"
            if BROWSE_ENABLED:
                status_msg += f" | 浏览:{self.browse_count} 点赞:{self.like_count}"
        else:
            status_msg = f"❌签到失败: {self.error_message}"

        # Gotify 通知
        if GOTIFY_URL and GOTIFY_TOKEN:
            try:
                response = requests.post(
                    f"{GOTIFY_URL}/message",
                    params={"token": GOTIFY_TOKEN},
                    json={"title": "LINUX DO", "message": status_msg, "priority": 1},
                    timeout=10,
                )
                response.raise_for_status()
                logger.success("消息已推送至Gotify")
            except Exception as e:
                logger.error(f"Gotify推送失败: {str(e)}")

        # Server酱³ 通知
        if SC3_PUSH_KEY:
            match = re.match(r"sct(\d+)t", SC3_PUSH_KEY, re.I)
            if not match:
                logger.error("❌ SC3_PUSH_KEY格式错误，未获取到UID，无法使用Server酱³推送")
            else:
                uid = match.group(1)
                url = f"https://{uid}.push.ft07.com/send/{SC3_PUSH_KEY}"
                params = {"title": "LINUX DO", "desp": status_msg}

                for attempt in range(3):
                    try:
                        response = requests.get(url, params=params, timeout=10)
                        response.raise_for_status()
                        logger.success(f"Server酱³推送成功")
                        break
                    except Exception as e:
                        logger.error(f"Server酱³推送失败: {str(e)}")
                        if attempt < 2:
                            time.sleep(random.randint(5, 10))

        # wxpush 通知
        if WXPUSH_URL and WXPUSH_TOKEN:
            try:
                response = requests.post(
                    f"{WXPUSH_URL}/wxsend",
                    headers={
                        "Authorization": WXPUSH_TOKEN,
                        "Content-Type": "application/json",
                    },
                    json={"title": "LINUX DO", "content": status_msg},
                    timeout=10,
                )
                response.raise_for_status()
                logger.success(f"wxpush 推送成功")
            except Exception as e:
                logger.error(f"wxpush 推送失败: {str(e)}")

    def run(self):
        try:
            login_res = self.login()
            if not login_res:
                logger.error("登录失败，程序终止")
                self.send_notifications(success=False)
                sys.exit(1)

            if BROWSE_ENABLED:
                click_topic_res = self.click_topic()
                if not click_topic_res:
                    logger.error("点击主题失败，程序终止")
                    self.send_notifications(success=False)
                    sys.exit(1)
                logger.info("完成浏览任务")

            self.send_notifications(success=True)
        finally:
            try:
                self.page.close()
            except Exception:
                pass
            try:
                self.browser.quit()
            except Exception:
                pass


if __name__ == "__main__":
    if not USERNAME or not PASSWORD:
        print("Please set USERNAME and PASSWORD")
        exit(1)
    l = LinuxDoBrowser()
    l.run()
