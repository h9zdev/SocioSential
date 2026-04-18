"""
Discord Bot for HayOS - Sends embedded messages and alerts to Discord channel
"""

import discord
from discord.ext import commands, tasks
import asyncio
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Discord Configuration
DISCORD_BOT_TOKEN = "YOUR_API_KEY"
DISCORD_CHANNEL_ID = YOUR_CHANNEL ID

# Initialize bot with intents
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.channels = True

bot = commands.Bot(command_prefix='!', intents=intents)

# Store message queue for async processing
message_queue = asyncio.Queue()


class DiscordBotManager:
    """Manages Discord bot interactions"""
    
    def __init__(self, token: str, channel_id: int):
        self.token = token
        self.channel_id = channel_id
        self.bot = bot
        self.channel = None
        self.is_ready = False
        
    async def send_embedded_message(self, 
                                    title: str, 
                                    description: str, 
                                    color: discord.Color = discord.Color.blue(),
                                    fields: Optional[List[Dict[str, Any]]] = None,
                                    footer: Optional[str] = None,
                                    image_url: Optional[str] = None) -> bool:
        """
        Send an embedded message to the specified channel
        
        Args:
            title: Title of the embed
            description: Main description text
            color: Color of the embed (discord.Color)
            fields: List of field dicts with 'name', 'value', 'inline' keys
            footer: Footer text
            image_url: URL for embed image
            
        Returns:
            bool: True if message sent successfully
        """
        try:
            if not self.is_ready or not self.channel:
                logger.error("Bot not ready or channel not found")
                return False
                
            embed = discord.Embed(
                title=title,
                description=description,
                color=color,
                timestamp=datetime.utcnow()
            )
            
            # Add fields if provided
            if fields:
                for field in fields:
                    name = field.get('name', 'Field')
                    value = field.get('value', 'No value')
                    inline = field.get('inline', False)
                    embed.add_field(name=name, value=value, inline=inline)
            
            # Add footer
            if footer:
                embed.set_footer(text=footer)
            else:
                embed.set_footer(text="HayOS Intelligence System")
            
            # Add image if provided
            if image_url:
                embed.set_image(url=image_url)
            
            # Send embed
            await self.channel.send(embed=embed)
            logger.info(f"Message sent: {title}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending embedded message: {e}")
            return False
    
    async def send_alert(self, alert_type: str, message: str, severity: str = "INFO"):
        """
        Send an alert message with severity level
        
        Args:
            alert_type: Type of alert (ANALYSIS, MONITOR, THREAT, etc.)
            message: Alert message content
            severity: Severity level (INFO, WARNING, CRITICAL)
        """
        # Color based on severity
        colors = {
            "INFO": discord.Color.blue(),
            "WARNING": discord.Color.orange(),
            "CRITICAL": discord.Color.red()
        }
        
        color = colors.get(severity, discord.Color.blue())
        
        # Severity emoji
        emojis = {
            "INFO": "ℹ️",
            "WARNING": "⚠️",
            "CRITICAL": "🚨"
        }
        
        emoji = emojis.get(severity, "")
        
        await self.send_embedded_message(
            title=f"{emoji} {alert_type} - {severity}",
            description=message,
            color=color,
            footer=f"Alert | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC"
        )
    
    async def send_reddit_analysis_report(self, 
                                         target: str,
                                         threat_level: str,
                                         threat_score: int,
                                         analysis_data: Dict[str, Any]):
        """Send a Reddit analysis report"""
        
        color_map = {
            "CRITICAL": discord.Color.red(),
            "ELEVATED": discord.Color.orange(),
            "HIGH": discord.Color.gold(),
            "MED": discord.Color.blue(),
            "LOW": discord.Color.green()
        }
        
        color = color_map.get(threat_level, discord.Color.blue())
        
        fields = [
            {"name": "Target", "value": target, "inline": True},
            {"name": "Threat Level", "value": threat_level, "inline": True},
            {"name": "Threat Score", "value": f"{threat_score}/100", "inline": True},
        ]
        
        # Add analysis fields if available
        if analysis_data.get('demographics'):
            demographics = analysis_data['demographics']
            fields.append({
                "name": "Demographics",
                "value": f"Age: {demographics.get('age_estimate', 'Unknown')}\nLocation: {demographics.get('location', 'Unknown')}",
                "inline": True
            })
        
        if analysis_data.get('occupation_indicators'):
            indicators = ", ".join(analysis_data['occupation_indicators'][:3])
            fields.append({
                "name": "Occupation Indicators",
                "value": indicators or "No data",
                "inline": False
            })
        
        if analysis_data.get('personality'):
            personality = analysis_data['personality']
            fields.append({
                "name": "Personality Profile",
                "value": f"Extraversion: {personality.get('extraversion', 0)}/100",
                "inline": True
            })
        
        await self.send_embedded_message(
            title=f"🔍 Reddit Analysis Report - {threat_level}",
            description=f"Analysis complete for `{target}`",
            color=color,
            fields=fields
        )
    
    async def send_monitor_created(self, target: str, monitor_type: str, monitor_id: str):
        """Send notification when a new monitor is created"""
        
        fields = [
            {"name": "Target", "value": target, "inline": True},
            {"name": "Type", "value": monitor_type, "inline": True},
            {"name": "Monitor ID", "value": monitor_id, "inline": True},
            {"name": "Status", "value": "🟢 Active", "inline": True},
            {"name": "Created", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "inline": True}
        ]
        
        await self.send_embedded_message(
            title="🛡️ New Surveillance Monitor Created",
            description=f"Monitor established for `{target}`",
            color=discord.Color.green(),
            fields=fields
        )
    
    async def send_threat_alert(self, target: str, threat_level: str, threat_score: int, details: str = ""):
        """Send a threat alert"""
        
        color_map = {
            "CRITICAL": discord.Color.red(),
            "HIGH": discord.Color.orange(),
            "MED": discord.Color.gold(),
            "LOW": discord.Color.green()
        }
        
        color = color_map.get(threat_level, discord.Color.blue())
        
        fields = [
            {"name": "Target", "value": target, "inline": True},
            {"name": "Threat Level", "value": threat_level, "inline": True},
            {"name": "Threat Score", "value": f"{threat_score}/100", "inline": True},
        ]
        
        if details:
            fields.append({"name": "Details", "value": details, "inline": False})
        
        await self.send_embedded_message(
            title=f"🚨 Threat Alert - {threat_level}",
            description=f"High threat activity detected for `{target}`",
            color=color,
            fields=fields
        )


# Create global bot manager instance
bot_manager = DiscordBotManager(DISCORD_BOT_TOKEN, DISCORD_CHANNEL_ID)


@bot.event
async def on_ready():
    """Bot ready event"""
    try:
        bot_manager.channel = bot.get_channel(DISCORD_CHANNEL_ID)
        if bot_manager.channel:
            bot_manager.is_ready = True
            logger.info(f"✓ Bot connected as {bot.user}")
            logger.info(f"✓ Ready to send messages to channel: {DISCORD_CHANNEL_ID}")
            
            # Send startup message
            await bot_manager.send_alert(
                "BOT_STARTUP",
                "HayOS Discord Bot initialized and ready for operation",
                "INFO"
            )
        else:
            logger.error(f"Channel {DISCORD_CHANNEL_ID} not found")
    except Exception as e:
        logger.error(f"Error in on_ready: {e}")


@bot.event
async def on_error(event, *args, **kwargs):
    """Handle errors"""
    logger.error(f"Discord bot error in {event}: {args}, {kwargs}")


def run_bot():
    """Run the bot in a separate thread"""
    try:
        logger.info("Starting Discord bot...")
        bot.run(DISCORD_BOT_TOKEN)
    except Exception as e:
        logger.error(f"Error running bot: {e}")


async def send_message_to_discord(title: str, description: str, **kwargs):
    """
    Async function to send message to Discord
    Can be used from Flask routes
    """
    if bot_manager.is_ready:
        return await bot_manager.send_embedded_message(title, description, **kwargs)
    else:
        logger.warning("Bot manager not ready, message not sent")
        return False


# Helper functions for easy importing
async def discord_reddit_analysis(target, threat_level, threat_score, analysis_data):
    """Send Reddit analysis report"""
    return await bot_manager.send_reddit_analysis_report(target, threat_level, threat_score, analysis_data)


async def discord_monitor_created(target, monitor_type, monitor_id):
    """Send monitor created notification"""
    return await bot_manager.send_monitor_created(target, monitor_type, monitor_id)


async def discord_threat_alert(target, threat_level, threat_score, details=""):
    """Send threat alert"""
    return await bot_manager.send_threat_alert(target, threat_level, threat_score, details)


async def discord_send_alert(alert_type, message, severity="INFO"):
    """Send generic alert"""
    return await bot_manager.send_alert(alert_type, message, severity)


if __name__ == "__main__":
    # Run bot directly
    run_bot()
