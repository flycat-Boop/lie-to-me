# 🕵️‍♂️ Lie to Me - Deception Honeypot
# 🕵️‍♂️ Lie to Me - 蓝队欺骗防御蜜罐

> ⚠️ **WARNING: This is NOT a pentest range! It's a Blue Team Deception Technology.**
> ⚠️ **警告：这不是红队靶场！这是一个蓝队欺骗防御系统 (Deception Technology)。**
> 
> All vulnerabilities here are fake. If you try to "pwn" it, you will only get a trolled screenshot and your IP will be permanently recorded.
> 这里的所有漏洞都是伪造的。如果你试图“打穿”它，你只会得到一张嘲讽截图，并被记录在案。

## 👩‍💻 About the Author / 关于作者

I am a girl who has been **self-learning cybersecurity for just 17 days**. After struggling with boring syntax, I decided to build something fun.
I hold a **Low-Voltage Electrician Certificate** and love hand-crafting ESP32-S3 and AI hardware terminals. In the process, I realized a truth: **The underlying logic of a backdoor and a honeypot is fundamentally the same** — it's just a matter of who controls it. 
Thus, this project was born, combining reverse social engineering with code.

我是一个**自学了仅仅 17 天**网络安全的女生。在死磕枯燥的语法之后，我决定写点好玩的东西。
我持有**低压电工证**，喜欢手搓 ESP32-S3 和 AI 硬件终端。在这个过程中我突然顿悟：**后门和蜜罐的底层逻辑其实是同源的**，只是控制权不同。
所以，我把反向社工（Reverse Social Engineering）的理念融入了代码，诞生了这个项目。

## ✨ Core Features / 核心玩法与特性

*   **🎭 Hyper-realistic Deception / 极致的拟真伪装**：
    Fake enterprise Admin Panels, fake `.env` files, fake AWS keys and DB passwords. Perfectly baiting the greed of script kiddies.
    伪造的企业级 Admin Panel、假的 `.env` 配置文件、逼真的 AWS 密钥与数据库密码，专钓“脚本小子”的贪婪。
*   **🏆 Steam-style Achievements / 成就系统**：
    No cold interceptions. Trigger hidden achievements like "Script Kiddie", "Quote Lover", and more.
    不再冷冰冰地拦截，而是触发【初出茅庐】、【单引号爱好者】等隐藏成就。
*   **🎬 The Truman Show / 楚门的世界**：
    Type `truman` or `reality` in the terminal to unlock a special easter egg. You think you are attacking reality? The audience is watching you.
    在终端输入 `truman` 或 `reality`，解锁专属彩蛋。你以为你在攻击真实世界，其实这场真人秀的观众都在看着你。
*   **🤝 Viral "Accomplice" Share / 病毒式“帮凶”传播**：
    Clicking share after being trolled triggers a typewriter effect, inviting your friends to become an "accomplice".
    被嘲讽后点击分享，会触发打字机特效，邀请你的朋友成为“共犯”。
*   **⚖️ Legal Defense / 法治防线**：
    Forensics-level JSONL logs and a Cybersecurity Law warning. Specially designed to handle angry red teamers who try to cross the line.
    内置取证级 JSONL 日志与《网络安全法》警告，专治被激怒后试图越界的红队。
*   **🛡️ Robust Security / 严密的底层安全**：
    While the frontend is acting, the backend uses `flock` file locking, Web root isolation, and XSS protection to ensure the honeypot itself never crashes.
    虽然前端在演戏，但后端我使用了 `flock` 文件锁、Web根目录隔离、防 XSS 转义，确保蜜罐自身绝不会被打崩。

## 🧠 Philosophy: Social Engineering > Technology
## 🧠 核心理念：社工大于技术

Traditional defense is "building a wall"; my approach is "building a fake vault".
By exploiting hackers' vanity, curiosity, and rage, we waste their time and harvest their payloads. 
**The best defense is deceiving them like a hacker.**

传统的防御是“建墙”，而我的思路是“建假金库”。
利用黑客的虚荣心、好奇心和被嘲讽后的愤怒，消耗他们的时间，收集他们的 Payload。**最好的防御，就是像黑客一样欺骗他们。**

## 🚀 Quick Start / 部署方式

No complex configuration needed, just a PHP environment:
无需复杂的配置，只需一个 PHP 环境：

1. Drop `index.php` into your Web server directory (e.g., Nginx/Apache).
   将 `index.php` 放入你的 Web 服务器目录。
2. Ensure directory write permissions (the system will automatically generate logs and ban lists outside the Web root).
   赋予目录写入权限（系统会自动在 Web 根目录外生成日志和封禁名单）。
3. Access the page and start phishing for hackers.
   访问页面，开始你的“钓鱼执法”。

*(Tip: Deploy behind a reverse proxy / CDN to hide your real IP.)*
*(提示：建议在生产环境部署时，配置反向代理 CDN 隐藏真实 IP。)*

## 📸 Screenshots / 真实测试截图
<img width="1910" height="689" alt="QQ20261106-215736" src="https://github.com/user-attachments/assets/de2cb507-a281-4d45-99b2-a0bf1912861c" />


---
*Disclaimer: This project is for Blue Team research, open-source education, and geek trolling only. Do NOT use it for any illegal purposes.*
*免责声明：本项目仅供蓝队防御研究、开源教育与极客整活。请勿用于任何非法用途。*
