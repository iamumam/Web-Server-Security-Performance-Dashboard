import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
import io
import base64
from datetime import datetime
import numpy as np
import warnings
warnings.filterwarnings('ignore')

# Set page configuration
st.set_page_config(
    page_title="Web Server Security & Performance Dashboard",
    page_icon="🔍",
    layout="wide"
)

# Custom CSS for better styling
st.markdown("""
<style>
/* Umum (default gelap) */
.metric-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 1rem;
    border-radius: 10px;
    color: white;
    text-align: center;
    margin: 0.5rem 0;
}
.insight-box, .danger-box {
    background-color: #383838;
    color: white;
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 5px;
}
.warning-box {
    background-color: #fff3cd;
    color: #333;
    border-left: 4px solid #ffc107;
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 5px;
}

/* Jika mode terang */
@media (prefers-color-scheme: light) {
    .metric-card {
        color: #222;
        background: linear-gradient(135deg, #dbeafe 0%, #ddd6f3 100%);
    }
    .insight-box, .danger-box {
        background-color: #f8f9fa;
        color: #222;
        border-left: 4px solid #007bff;
    }
    .danger-box {
        border-left: 4px solid #dc3545;
    }
}
</style>
""", unsafe_allow_html=True)

# Title and introduction
st.title("🔍 Web Server Security & Performance Dashboard")
st.markdown("""
**Analisis Komprehensif Log Akses Server untuk Monitoring Keamanan dan Performa**

Dashboard ini dirancang untuk membantu administrator sistem dalam:
- 🛡️ **Deteksi Ancaman Keamanan** - Identifikasi pola akses mencurigakan
- 📊 **Monitoring Performa** - Analisis beban server dan response time
- 🤖 **Bot Intelligence** - Membedakan traffic legitim vs malicious
- 🚨 **Alert System** - Peringatan dini untuk anomali traffic
""")

st.markdown("---")

# Function to parse logs with enhanced error handling
def parse_logs(log_content):
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s'                  # IP address
        r'- - \[(?P<datetime>[^\]]+)\]\s'                 # Timestamp
        r'"(?P<method>\w+)\s(?P<url>\S+)\sHTTP/\d\.\d"\s' # HTTP Method, URL
        r'(?P<status>\d{3})\s(?P<size>\d+|-)\s'           # Status code, Size
        r'"(?P<referrer>[^"]*)"\s'                        # Referrer
        r'"(?P<user_agent>[^"]*)"'                        # User Agent
    )
    
    log_data = []
    failed_lines = 0
    
    for line in log_content.split('\n'):
        if line.strip():
            match = log_pattern.match(line)
            if match:
                entry = match.groupdict()
                entry['size'] = int(entry['size']) if entry['size'] != '-' else 0
                log_data.append(entry)
            else:
                failed_lines += 1
    
    # Create DataFrame with enhanced processing
    df = pd.DataFrame(log_data)
    if not df.empty:
        df['status'] = df['status'].astype(int)
        df['datetime'] = pd.to_datetime(df['datetime'], format="%d/%b/%Y:%H:%M:%S %z")
        df['hour'] = df['datetime'].dt.hour
        df['date'] = df['datetime'].dt.date
        
        # Add security classifications
        df['is_suspicious'] = df.apply(lambda x: is_suspicious_request(x), axis=1)
        df['bot_type'] = df['user_agent'].apply(classify_bot)
        df['request_risk'] = df.apply(lambda x: calculate_risk_score(x), axis=1)
    
    return df, failed_lines

# Enhanced bot classification
def classify_bot(user_agent):
    ua_lower = user_agent.lower()
    
    # Search engine bots (legitimate)
    if any(bot in ua_lower for bot in ['googlebot', 'bingbot', 'slurp', 'duckduckbot']):
        return 'Search Engine'
    
    # Social media crawlers
    if any(bot in ua_lower for bot in ['facebookexternalhit', 'twitterbot', 'linkedinbot']):
        return 'Social Media'
    
    # Monitoring/SEO tools
    if any(bot in ua_lower for bot in ['pingdom', 'uptimerobot', 'semrushbot', 'ahrefsbot']):
        return 'Monitoring/SEO'
    
    # Generic bots or crawlers
    if any(pattern in ua_lower for pattern in ['bot', 'crawl', 'spider', 'scraper']):
        return 'Generic Bot'
    
    # Suspicious patterns
    if any(pattern in ua_lower for pattern in ['python', 'curl', 'wget', 'scanner']):
        return 'Potentially Suspicious'
    
    return 'Human'

# Security risk assessment
def is_suspicious_request(row):
    suspicious_patterns = [
        '/admin', '/wp-admin', '/.env', '/config', 
        'phpinfo', 'eval(', '<script>', 'union select',
        '../', '..\\', '/etc/passwd'
    ]
    
    # Check URL for suspicious patterns
    url_suspicious = any(pattern in row['url'].lower() for pattern in suspicious_patterns)
    
    # Check for unusual status codes
    status_suspicious = row['status'] in [401, 403, 500, 503]
    
    # Check for high-frequency requests from same IP (this would need groupby analysis)
    return url_suspicious or status_suspicious

def calculate_risk_score(row):
    score = 0
    
    # Status code risk
    if row['status'] >= 400:
        score += 2
    if row['status'] >= 500:
        score += 1
    
    # Suspicious request patterns
    if row['is_suspicious']:
        score += 3
    
    # Bot type risk
    if row['bot_type'] == 'Potentially Suspicious':
        score += 4
    elif row['bot_type'] == 'Generic Bot':
        score += 1
    
    return min(score, 10)  # Cap at 10

# Sidebar configuration
st.sidebar.header("🔧 Configuration")
uploaded_file = st.sidebar.file_uploader("Upload Access Log File", type=["log", "txt"])
use_example_data = st.sidebar.checkbox("Use Demo Data", value=True)

# Enhanced sample data with security scenarios
if uploaded_file is not None:
    log_content = uploaded_file.getvalue().decode("utf-8")
    df, failed_lines = parse_logs(log_content)
    if failed_lines > 0:
        st.sidebar.warning(f"⚠️ {failed_lines} lines could not be parsed")
    st.sidebar.success(f"✅ Successfully loaded {len(df)} log entries")
elif use_example_data:
    sample_logs = """
66.249.66.194 - - [12/Jan/2020:09:15:35 +0000] "GET /settings/logo HTTP/1.1" 200 3456 "https://example.com/dashboard" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
66.249.66.91 - - [12/Jan/2020:09:16:12 +0000] "GET /static/css/main.css HTTP/1.1" 200 1234 "https://example.com/products" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
207.46.13.9 - - [12/Jan/2020:09:17:05 +0000] "GET / HTTP/1.1" 200 7890 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
23.101.169.3 - - [12/Jan/2020:09:18:23 +0000] "GET /products/laptop HTTP/1.1" 200 4567 "https://google.com/search" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
185.220.101.32 - - [12/Jan/2020:09:19:45 +0000] "GET /admin/login HTTP/1.1" 403 1234 "-" "python-requests/2.25.1"
185.220.101.32 - - [12/Jan/2020:09:19:47 +0000] "GET /wp-admin/ HTTP/1.1" 404 567 "-" "python-requests/2.25.1"
185.220.101.32 - - [12/Jan/2020:09:19:49 +0000] "GET /.env HTTP/1.1" 404 567 "-" "python-requests/2.25.1"
185.220.101.32 - - [12/Jan/2020:09:19:51 +0000] "GET /config.php HTTP/1.1" 404 567 "-" "python-requests/2.25.1"
192.168.1.105 - - [12/Jan/2020:09:20:10 +0000] "GET /dashboard HTTP/1.1" 200 2345 "https://example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
192.168.1.105 - - [12/Jan/2020:09:21:30 +0000] "POST /api/orders HTTP/1.1" 201 1122 "https://example.com/checkout" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
10.0.0.15 - - [12/Jan/2020:14:15:35 +0000] "GET /health HTTP/1.1" 200 100 "-" "Pingdom.com_bot_version_1.4"
40.77.167.170 - - [12/Jan/2020:14:16:15 +0000] "GET /sitemap.xml HTTP/1.1" 200 2233 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
91.99.72.15 - - [12/Jan/2020:14:17:05 +0000] "GET /api/users/1 HTTP/1.1" 401 321 "-" "curl/7.68.0"
91.99.72.15 - - [12/Jan/2020:14:17:07 +0000] "GET /api/users/2 HTTP/1.1" 401 321 "-" "curl/7.68.0"
91.99.72.15 - - [12/Jan/2020:14:17:09 +0000] "GET /api/users/3 HTTP/1.1" 401 321 "-" "curl/7.68.0"
198.51.100.42 - - [12/Jan/2020:14:18:23 +0000] "GET /products/phone HTTP/1.1" 200 3456 "https://example.com/search" "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15"
198.51.100.42 - - [12/Jan/2020:14:19:01 +0000] "POST /contact HTTP/1.1" 200 789 "https://example.com/contact" "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15"
66.249.66.194 - - [12/Jan/2020:14:20:10 +0000] "GET /robots.txt HTTP/1.1" 200 456 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
203.0.113.25 - - [12/Jan/2020:14:21:45 +0000] "GET /server-status HTTP/1.1" 403 234 "-" "Wget/1.20.3 (linux-gnu)"
172.16.0.50 - - [12/Jan/2020:14:22:30 +0000] "GET /internal/monitoring HTTP/1.1" 500 1987 "-" "UptimeRobot/2.0"
185.220.101.32 - - [12/Jan/2020:14:23:10 +0000] "GET /admin/config HTTP/1.1" 403 567 "-" "python-requests/2.25.1"
185.220.101.32 - - [12/Jan/2020:14:23:12 +0000] "GET /admin/users HTTP/1.1" 403 567 "-" "python-requests/2.25.1"
91.99.72.15 - - [12/Jan/2020:14:23:15 +0000] "GET /api/admin/users HTTP/1.1" 401 321 "-" "curl/7.68.0"
91.99.72.15 - - [12/Jan/2020:14:23:17 +0000] "GET /api/admin/config HTTP/1.1" 401 321 "-" "curl/7.68.0"
203.0.113.25 - - [12/Jan/2020:14:23:20 +0000] "GET /phpinfo.php HTTP/1.1" 404 234 "-" "Wget/1.20.3 (linux-gnu)"
"""
    df, failed_lines = parse_logs(sample_logs)
    st.sidebar.info(f"📊 Demo data loaded: {len(df)} entries")

# Main analysis
if df is not None and not df.empty:
    
    # Security Dashboard Header
    st.header("🛡️ Security Overview")
    
    # Key Security Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        suspicious_count = df['is_suspicious'].sum()
        suspicious_pct = (suspicious_count / len(df)) * 100
        st.markdown(f"""
        <div class="metric-card">
            <h3>{suspicious_count:,}</h3>
            <p>Suspicious Requests</p>
            <small>{suspicious_pct:.1f}% of total</small>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        high_risk_count = (df['request_risk'] >= 5).sum()
        st.markdown(f"""
        <div class="metric-card">
            <h3>{high_risk_count:,}</h3>
            <p>High Risk Events</p>
            <small>Risk Score ≥ 5</small>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        unique_attackers = df[df['is_suspicious']]['ip'].nunique()
        st.markdown(f"""
        <div class="metric-card">
            <h3>{unique_attackers:,}</h3>
            <p>Potential Attackers</p>
            <small>Unique IPs</small>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        error_rate = (df['status'] >= 400).mean() * 100
        st.markdown(f"""
        <div class="metric-card">
            <h3>{error_rate:.1f}%</h3>
            <p>Error Rate</p>
            <small>4xx + 5xx responses</small>
        </div>
        """, unsafe_allow_html=True)

    # Critical Security Alerts
    if suspicious_count > 0:
        st.markdown(f"""
        <div class="danger-box">
            <h4>🚨 SECURITY ALERT</h4>
            <p><strong>{suspicious_count} suspicious requests detected!</strong></p>
            <p>Immediate actions recommended:</p>
            <ul>
                <li>Review IP addresses: {', '.join(df[df['is_suspicious']]['ip'].unique()[:5])}</li>
                <li>Check for brute force attempts</li>
                <li>Verify firewall rules</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    # Primary Analysis Tabs
    tab1, tab2, tab3 = st.tabs(["🔍 Threat Analysis", "🤖 Bot Intelligence", "📈 Performance Insights"])
    
    with tab1:
        st.subheader("Security Threat Analysis")
        
        # IP Risk Analysis
        ip_risk = df.groupby('ip').agg({
            'request_risk': ['sum', 'mean', 'count'],
            'is_suspicious': 'sum',
            'status': lambda x: (x >= 400).sum()
        }).round(2)
        
        ip_risk.columns = ['Total_Risk', 'Avg_Risk', 'Request_Count', 'Suspicious_Count', 'Error_Count']
        ip_risk = ip_risk.sort_values('Total_Risk', ascending=False).reset_index()
        
        # Display top risky IPs
        st.markdown("**🎯 Top Risk IP Addresses**")
        
        top_risky_ips = ip_risk.head(8)
        if len(top_risky_ips) > 0:
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            
            # Risk score by IP
            colors = ['red' if risk >= 10 else 'orange' if risk >= 5 else 'yellow' 
                     for risk in top_risky_ips['Total_Risk']]
            
            ax1.barh(range(len(top_risky_ips)), top_risky_ips['Total_Risk'], color=colors)
            ax1.set_yticks(range(len(top_risky_ips)))
            ax1.set_yticklabels(top_risky_ips['ip'])
            ax1.set_xlabel('Total Risk Score')
            ax1.set_title('IP Addresses by Risk Score')
            ax1.invert_yaxis()
            
            # FIXED: Request patterns scatter plot
            # Ensure we have valid data to plot
            x_data = top_risky_ips['Request_Count']
            y_data = top_risky_ips['Suspicious_Count']
            sizes = np.maximum(top_risky_ips['Total_Risk'] * 30, 50)  # Minimum size 50, scale factor 30
            colors_scatter = top_risky_ips['Total_Risk']
            
            # Create scatter plot with better visibility
            scatter = ax2.scatter(x_data, y_data, s=sizes, alpha=0.7, 
                                c=colors_scatter, cmap='Reds', edgecolors='black', linewidth=1)
            
            # Add labels for each point
            for i, (x, y, ip) in enumerate(zip(x_data, y_data, top_risky_ips['ip'])):
                ax2.annotate(f'{ip}', (x, y), xytext=(5, 5), 
                           textcoords='offset points', fontsize=8, alpha=0.8)
            
            ax2.set_xlabel('Total Requests')
            ax2.set_ylabel('Suspicious Requests')
            ax2.set_title('Request Volume vs Suspicious Activity\n(Bubble size = Risk Score)')
            ax2.grid(True, alpha=0.3)
            
            # Add colorbar for risk score
            cbar = plt.colorbar(scatter, ax=ax2)
            cbar.set_label('Risk Score', rotation=270, labelpad=15)
            
            # Set axis limits to ensure all points are visible
            if len(x_data) > 0 and len(y_data) > 0:
                ax2.set_xlim(min(x_data) - 0.5, max(x_data) + 0.5)
                ax2.set_ylim(min(y_data) - 0.5, max(y_data) + 0.5)
            
            plt.tight_layout()
            st.pyplot(fig)
            
            # Show data table for verification
            st.markdown("**📊 IP Risk Analysis Data**")
            display_df = top_risky_ips.copy()
            display_df = display_df.round(2)
            st.dataframe(display_df, use_container_width=True)
            
            # Risk interpretation
            highest_risk_ip = top_risky_ips.iloc[0]
            if highest_risk_ip['Total_Risk'] >= 10:
                st.markdown(f"""
                <div class="danger-box">
                    <h4>⚠️ CRITICAL THREAT DETECTED</h4>
                    <p>IP <strong>{highest_risk_ip['ip']}</strong> shows extremely suspicious behavior:</p>
                    <ul>
                        <li>Risk Score: <strong>{highest_risk_ip['Total_Risk']}</strong></li>
                        <li>Total Requests: <strong>{highest_risk_ip['Request_Count']}</strong></li>
                        <li>Suspicious Requests: <strong>{highest_risk_ip['Suspicious_Count']}</strong></li>
                        <li><strong>Immediate blocking recommended</strong></li>
                    </ul>
                </div>
                """, unsafe_allow_html=True)
            
        # Attack pattern analysis
        if df['is_suspicious'].any():
            st.markdown("**🔍 Attack Patterns Detected**")
            
            suspicious_urls = df[df['is_suspicious']]['url'].value_counts().head(10)
            
            fig, ax = plt.subplots(figsize=(12, 6))
            suspicious_urls.plot(kind='barh', ax=ax, color='crimson')
            ax.set_title('Most Targeted URLs')
            ax.set_xlabel('Attack Attempts')
            plt.tight_layout()
            st.pyplot(fig)
            
            st.markdown(f"""
            <div class="insight-box">
                <h4>🎯 Attack Pattern Analysis</h4>
                <ul>
                    <li><strong>Top Target:</strong> {suspicious_urls.index[0]} ({suspicious_urls.iloc[0]} attempts)</li>
                    <li><strong>Attack Types:</strong> Admin panel probing, config file access, environment variable exposure</li>
                    <li><strong>Recommendation:</strong> Implement rate limiting and IP blocking for these endpoints</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

    with tab2:
        st.subheader("Bot Traffic Intelligence")
        
        # Bot classification analysis
        bot_analysis = df['bot_type'].value_counts()
        
        col1, col2 = st.columns(2)
        
        with col1:
            fig, ax = plt.subplots(figsize=(10, 8))
            colors = {'Human': '#2E8B57', 'Search Engine': '#4169E1', 
                     'Social Media': '#FF6347', 'Monitoring/SEO': '#FFD700',
                     'Generic Bot': '#FFA500', 'Potentially Suspicious': '#DC143C'}
            
            wedges, texts, autotexts = ax.pie(bot_analysis.values, labels=bot_analysis.index, 
                                            autopct='%1.1f%%', startangle=90,
                                            colors=[colors.get(label, '#808080') for label in bot_analysis.index])
            ax.set_title('Traffic Source Classification')
            plt.tight_layout()
            st.pyplot(fig)
        
        with col2:
            # Bot behavior analysis
            bot_behavior = df.groupby('bot_type').agg({
                'status': lambda x: (x >= 400).mean() * 100,
                'size': 'mean',
                'ip': 'nunique'
            }).round(2)
            bot_behavior.columns = ['Error_Rate_%', 'Avg_Response_Size', 'Unique_IPs']
            
            st.markdown("**Bot Behavior Metrics**")
            st.dataframe(bot_behavior)
        
        # Detailed bot insights
        human_traffic = (df['bot_type'] == 'Human').sum()
        legitimate_bots = df['bot_type'].isin(['Search Engine', 'Social Media', 'Monitoring/SEO']).sum()
        suspicious_bots = (df['bot_type'] == 'Potentially Suspicious').sum()
        
        st.markdown(f"""
        <div class="insight-box">
            <h4>🤖 Bot Traffic Intelligence Summary</h4>
            <ul>
                <li><strong>Human Traffic:</strong> {human_traffic} requests ({(human_traffic/len(df)*100):.1f}%)</li>
                <li><strong>Legitimate Bots:</strong> {legitimate_bots} requests (search engines, social crawlers)</li>
                <li><strong>Suspicious Bots:</strong> {suspicious_bots} requests - <span style="color: red;">Requires attention</span></li>
            </ul>
            <p><strong>Key Insight:</strong> 
            {'High bot traffic is normal for public sites, but monitor for unusual patterns.' if legitimate_bots > suspicious_bots 
             else 'Elevated suspicious bot activity detected - implement bot protection measures.'}</p>
        </div>
        """, unsafe_allow_html=True)

    with tab3:
        st.subheader("Performance & Availability Insights")
        
        # Performance metrics by hour
        hourly_performance = df.groupby('hour').agg({
            'ip': 'count',
            'status': lambda x: (x >= 400).mean() * 100,
            'size': 'mean'
        }).round(2)
        hourly_performance.columns = ['Requests', 'Error_Rate_%', 'Avg_Response_Size']
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Traffic volume
        axes[0,0].plot(hourly_performance.index, hourly_performance['Requests'], 
                      marker='o', linewidth=2, color='blue')
        axes[0,0].set_title('Hourly Request Volume')
        axes[0,0].set_xlabel('Hour of Day')
        axes[0,0].set_ylabel('Number of Requests')
        axes[0,0].grid(True, alpha=0.3)
        
        # Error rate
        axes[0,1].plot(hourly_performance.index, hourly_performance['Error_Rate_%'], 
                      marker='s', linewidth=2, color='red')
        axes[0,1].set_title('Hourly Error Rate')
        axes[0,1].set_xlabel('Hour of Day')
        axes[0,1].set_ylabel('Error Rate (%)')
        axes[0,1].grid(True, alpha=0.3)
        
        # Status code distribution
        status_dist = df['status'].value_counts().sort_index()
        axes[1,0].bar(status_dist.index.astype(str), status_dist.values, 
                     color=['green' if x < 300 else 'orange' if x < 400 else 'red' for x in status_dist.index])
        axes[1,0].set_title('HTTP Status Code Distribution')
        axes[1,0].set_xlabel('Status Code')
        axes[1,0].set_ylabel('Count')
        
        # Response size distribution
        df['size_mb'] = df['size'] / (1024*1024)
        axes[1,1].hist(df['size_mb'][df['size_mb'] < 1], bins=20, alpha=0.7, color='purple')
        axes[1,1].set_title('Response Size Distribution (MB)')
        axes[1,1].set_xlabel('Size (MB)')
        axes[1,1].set_ylabel('Frequency')
        
        plt.tight_layout()
        st.pyplot(fig)
        
        # Performance insights
        peak_hour = hourly_performance['Requests'].idxmax()
        peak_requests = hourly_performance['Requests'].max()
        highest_error_hour = hourly_performance['Error_Rate_%'].idxmax()
        highest_error_rate = hourly_performance['Error_Rate_%'].max()
        
        st.markdown(f"""
        <div class="insight-box">
            <h4>📊 Performance Analysis</h4>
            <ul>
                <li><strong>Peak Traffic Hour:</strong> {peak_hour}:00 with {peak_requests} requests</li>
                <li><strong>Highest Error Rate:</strong> {highest_error_rate:.1f}% at {highest_error_hour}:00</li>
                <li><strong>Avg Response Size:</strong> {df['size'].mean()/1024:.1f} KB</li>
                <li><strong>System Health:</strong> {'🟢 Good' if highest_error_rate < 5 else '🟡 Attention Needed' if highest_error_rate < 15 else '🔴 Critical Issues'}</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    # Action Items Summary
    st.header("🎯 Recommended Actions")
    
    # Generate dynamic recommendations
    recommendations = []
    
    if suspicious_count > 0:
        recommendations.append(f"🔒 **SECURITY:** Block or monitor {df[df['is_suspicious']]['ip'].nunique()} suspicious IP addresses")
    
    if (df['request_risk'] >= 7).any():
        recommendations.append("🚨 **URGENT:** Investigate high-risk security events immediately")
    
    if error_rate > 10:
        recommendations.append(f"⚠️ **PERFORMANCE:** Address high error rate ({error_rate:.1f}%) - check server health")
    
    if (df['bot_type'] == 'Potentially Suspicious').sum() > len(df) * 0.1:
        recommendations.append("🤖 **BOT PROTECTION:** Implement CAPTCHA or rate limiting for suspicious bots")
    
    if len(recommendations) == 0:
        recommendations.append("✅ **STATUS:** No critical issues detected - maintain current monitoring")
    
    for i, rec in enumerate(recommendations, 1):
        st.markdown(f"{i}. {rec}")
    
    # Export functionality
    st.header("💾 Export Analysis Results")
    
    # Create comprehensive report
    security_report = df[df['is_suspicious']][['datetime', 'ip', 'url', 'status', 'user_agent', 'request_risk']]
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Download Security Report"):
            csv = security_report.to_csv(index=False)
            b64 = base64.b64encode(csv.encode()).decode()
            href = f'<a href="data:file/csv;base64,{b64}" download="security_report_{datetime.now().strftime("%Y%m%d")}.csv">Download Security Report CSV</a>'
            st.markdown(href, unsafe_allow_html=True)
    
    with col2:
        if st.button("Download Full Analysis"):
            csv = df.to_csv(index=False)
            b64 = base64.b64encode(csv.encode()).decode()
            href = f'<a href="data:file/csv;base64,{b64}" download="full_log_analysis_{datetime.now().strftime("%Y%m%d")}.csv">Download Complete Analysis CSV</a>'
            st.markdown(href, unsafe_allow_html=True)

else:
    # Instructions for new users
    st.markdown("""
    <div class="insight-box">
        <h3>🚀 Get Started</h3>
        <p>Upload your web server access logs or use the demo data to begin security analysis.</p>
        <p><strong>Supported log format:</strong> Apache/Nginx Common Log Format</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.code('''
    Example log entry:
    192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://referrer.com" "Mozilla/5.0..."
    ''')

# Footer
st.markdown("---")
st.markdown(f"*Security Dashboard generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Stay vigilant, stay secure! 🔐*")