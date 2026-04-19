# 🌐 SocioSential  

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![OSINT](https://img.shields.io/badge/OSINT-Framework-purple?style=for-the-badge)](https://github.com/h9zdev/SocioSential)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen?style=for-the-badge)](https://github.com/h9zdev/SocioSential)
[![SocioSential](https://img.shields.io/badge/SocioSential-Active-red?style=for-the-badge)](https://github.com/h9zdev/SocioSential)

</div>

<p align="center">
  <img src="https://github.com/h9zdev/h9zdev/blob/main/assets/SocioSential.png?raw=true" alt="SocioSential" />
</p>


## 🧠 Overview  

**SocioSential** is an open-source OSINT intelligence framework designed to map the pulse of digital societies in real time.  

It collects and analyzes public social data to uncover emotional patterns, behavioral anomalies, and shifting sentiment across communities and networks.  

By transforming raw social signals into structured insight, SocioSential enables researchers, analysts, and security professionals to detect emerging narratives, monitor socio-political trends, and make informed, data-driven decisions. 🚀  

> [!TIP]
> - 🚀 **Visit the Blog (Geo Sentinel Updates & Insights)** [[🌐 Open Blog]](https://haybnz.web.app/blog)
> - 🚀 **Official Website** [[🌍 Visit Site]](https://haybnz.web.app/)
> - 🚀 **Official Website** [[🌍 Visit Site]](https://varadaraj.online/)

> [!CAUTION]
> - 🚨 **SocioSential** — Stay updated with the latest **Socio Sentinel AI** releases and announcements. [[📝 Subscribe Here]](https://docs.google.com/forms/d/e/1FAIpQLSe3qBh6r1orih2MkLf5DjdolX0jv5Abct02363lLxpXEute-Q/viewform)
> - SociSentail currently supports Twitter and Reddit OSINT, behavioral and sentiment analysis. Additional other social media intelligence modules and features are actively under development.

## ⚡ Features  

- 📡 Real-time social data aggregation  
- 🧠 Sentiment and behavioral analysis  
- 🌐 Community and network mapping  
- 🔍 Detection of anomalies and trend shifts  
- 📊 Actionable socio-political intelligence  

---

## 🚀 Use Cases  

- Social sentiment monitoring  
- Narrative and influence tracking  
- OSINT investigations  
- Behavioral analysis of online communities and the user.
- Early detection of socio-political shifts  

---

## 🔗 Repository  

👉 https://github.com/h9zdev/SocioSential

## 📋 Requirements

- Python 3.8+
- Redis (for Celery background tasks)
- API Keys for social platforms and AI providers (optional but recommended)

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/h9zdev/SocioSential.git
   cd SocioSential
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database**:
   The application uses SQLite and will automatically initialize `socio.db` on first run.

## ⚙️ Configuration

Create a `.env` file in the root directory or set the following environment variables:

```env
# Flask Configuration
FLASK_SECRET_KEY=your_secret_key_here

# Celery / Redis Configuration
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Twitter API (v2)
TWITTER_BEARER_TOKEN=your_bearer_token

# AI Provider Keys
OPENAI_API_KEY=your_openai_key
HF_TOKEN=your_huggingface_token
OPENROUTER_API_KEY=your_openrouter_key
OLLAMA_BASE_URL=http://localhost:11434

# Discord Integration
DISCORD_WEBHOOK_URL=your_webhook_url
DISCORD_BOT_TOKEN=your_bot_token
DISCORD_CHANNEL_ID=your_target_channel_id

# Database
SOCIO_DB_FILE=socio.db
```


## 🏃 Running the Application

### 1. Start the Web Server
```bash
python Socio.py
```
The application will be available at `http://127.0.0.1:5000`.

### 2. Start the Celery Worker (for background monitoring)
```bash
celery -A Socio.celery worker --loglevel=info
```

### 3. Start the Discord Bot (optional)
```bash
python bot.py
```

## 📖 API INSTRUCTIONS
 -need to config api's  in  Socio.py, bot.py and reddit.py
 
## 📖 Usage

1. **Dashboard**: Access the main interface to navigate between Twitter and Reddit modules.
2. **Twitter OSINT**: Enter a username to perform reconnaissance. Use the "Neural" tab for AI analysis.
3. **Reddit OSINT**: Search for users or subreddits. Establish "Surveillance" to receive automated alerts on threat spikes.
4. **Monitoring**: View active monitors in the Reddit Surveillance tab to track threat scores over time.
5. **Exports**: Generate PDF reports of your findings for professional documentation.


## 🛡️ Disclaimer

This tool is for educational and professional research purposes only. Users are responsible for complying with the Terms of Service of the social platforms accessed and all applicable local and international laws.



## 📜 License

This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) License. See the [LICENSE](LICENSE) file for more details.

**Unauthorized use is strictly prohibited.**

📧 Contact: singularat@protn.me

## ☕ Support

Donate via Monero: `45PU6txuLxtFFcVP95qT2xXdg7eZzPsqFfbtZp5HTjLbPquDAugBKNSh1bJ76qmAWNGMBCKk4R1UCYqXxYwYfP2wTggZNhq`

## 👥 Contributors and Developers

[<img src="https://avatars.githubusercontent.com/u/67865621?s=64&v=4" width="64" height="64" alt="haybnzz">](https://github.com/h9zdev)  
[<img src="https://avatars.githubusercontent.com/u/220222050?v=4&size=64" width="64" height="64" alt="H9yzz">](https://github.com/H9yzz)  
[<img src="https://avatars.githubusercontent.com/u/108749445?s=64&size=64" width="64" height="64" alt="VaradScript">](https://github.com/VaradScript)  
[<img src="https://avatars.githubusercontent.com/u/180658853?s=64&v=4" width="64" height="64" alt="Steiynbrodt">](https://github.com/Steiynbrodt)  

## 👥 
 X9 CYBERNETICS


## Star History

<a href="https://www.star-history.com/#h9zdev/GeoSentinel&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=h9zdev/GeoSentinel&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=h9zdev/GeoSentinel&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=h9zdev/GeoSentinel&type=date&legend=top-left" />
 </picture>
</a>


Made with ❤️ and lots of ☕️.

