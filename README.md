# SocioSential

SocioSential is an advanced, open-source OSINT (Open Source Intelligence) framework designed for social data collection and analysis. It enables researchers, analysts, and security professionals to surface emotional patterns, behavioral anomalies, and sentiment shifts across communities and networks.

Built with a focus on actionable socio-political intelligence, SocioSential leverages modern AI engines to provide deep insights into social media targets.

## 🚀 Features

- **Twitter Neural Reconnaissance**: Analyze user profiles, tweets, and engagement metrics. Mapping of social connections and influence.
- **Reddit Community Intelligence**: Comprehensive scanning of users (`u/`) and subreddits (`r/`).
- **5-Layer Intelligence Analysis**:
  - **Layer 1: Sentiment & Ideology**: Detects emotional tone and worldviews.
  - **Layer 2: Narrative & Stance**: Analyzes framing and institutional stances.
  - **Layer 3: Behavioral Analysis**: Detects posting patterns, automation (bot) indicators, and temporal spikes.
  - **Layer 4: Network Structure (SNA)**: Maps influence flow and community clusters.
  - **Layer 5: Threat & Political Status**: Assesses national threat levels, election interference, and brand reputation shifts.
- **Multi-Engine AI Support**: Seamlessly switch between OpenAI, Hugging Face, Ollama (local), and OpenRouter.
- **Active Surveillance & Monitoring**: Automated target monitoring with threat score tracking.
- **Discord Alert System**: Real-time intelligence delivery via Discord Webhooks and a dedicated Discord Bot.
- **Interactive Visualizations**: Dynamic charts, network graphs, and geospatial mapping.
- **Data Export**: Professional PDF reports, JSON, and CSV data exports.

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

## 📖 Usage

1. **Dashboard**: Access the main interface to navigate between Twitter and Reddit modules.
2. **Twitter OSINT**: Enter a username to perform reconnaissance. Use the "Neural" tab for AI analysis.
3. **Reddit OSINT**: Search for users or subreddits. Establish "Surveillance" to receive automated alerts on threat spikes.
4. **Monitoring**: View active monitors in the Reddit Surveillance tab to track threat scores over time.
5. **Exports**: Generate PDF reports of your findings for professional documentation.

## ⚖️ License

SocioSential is released under the MIT License. See [LICENSE](LICENSE) for details.

## 🛡️ Disclaimer

This tool is for educational and professional research purposes only. Users are responsible for complying with the Terms of Service of the social platforms accessed and all applicable local and international laws.
