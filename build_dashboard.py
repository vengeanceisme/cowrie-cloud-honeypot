import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

conn = sqlite3.connect('honeypot.db')

# Load data
events = pd.read_sql_query("SELECT * FROM events", conn)
locations = pd.read_sql_query("SELECT * FROM ip_locations", conn)

events['timestamp'] = pd.to_datetime(events['timestamp'])

# --- Chart 1: Top attacker IPs ---
top_ips = events['src_ip'].value_counts().head(15).reset_index()
top_ips.columns = ['src_ip', 'count']
fig1 = px.bar(top_ips, x='src_ip', y='count', title='Top 15 Attacker IPs by Event Count',
              labels={'src_ip': 'Source IP', 'count': 'Number of Events'})
fig1.update_layout(xaxis_tickangle=-45)

# --- Chart 2: Top usernames tried ---
logins = events[events['eventid'].str.contains('login', na=False)]
top_users = logins['username'].value_counts().head(15).reset_index()
top_users.columns = ['username', 'count']
fig2 = px.bar(top_users, x='username', y='count', title='Most Attempted Usernames',
              labels={'username': 'Username', 'count': 'Attempts'})

# --- Chart 3: Top passwords tried ---
top_pass = logins['password'].value_counts().head(15).reset_index()
top_pass.columns = ['password', 'count']
fig3 = px.bar(top_pass, x='password', y='count', title='Most Attempted Passwords',
              labels={'password': 'Password', 'count': 'Attempts'})

# --- Chart 4: Attacks over time ---
events_per_hour = events.set_index('timestamp').resample('1H').size().reset_index()
events_per_hour.columns = ['timestamp', 'count']
fig4 = px.line(events_per_hour, x='timestamp', y='count', title='Attack Events Over Time (Hourly)',
               labels={'timestamp': 'Time', 'count': 'Event Count'})

# --- Chart 5: World map of attacker locations ---
map_data = locations.dropna(subset=['lat', 'lon'])
fig5 = px.scatter_geo(map_data, lat='lat', lon='lon', hover_name='src_ip',
                       hover_data=['country', 'city'],
                       title='Attacker Locations Worldwide',
                       projection='natural earth')
fig5.update_traces(marker=dict(size=10, color='red'))

# --- Chart 6: Top countries ---
country_counts = locations['country'].value_counts().reset_index()
country_counts.columns = ['country', 'count']
fig6 = px.bar(country_counts, x='country', y='count', title='Attacks by Country',
              labels={'country': 'Country', 'count': 'Unique IPs'})
fig6.update_layout(xaxis_tickangle=-45)

# --- Build combined HTML page ---
html_parts = []
html_parts.append("<html><head><title>Honeypot Dashboard</title>")
html_parts.append("<style>body{font-family:Arial;background:#1e1e2e;color:#fff;margin:20px;} h1{text-align:center;} .chart{margin-bottom:40px;}</style>")
html_parts.append("</head><body>")
html_parts.append("<h1>🍯 Cowrie Honeypot Attack Dashboard</h1>")
html_parts.append(f"<p style='text-align:center;'>Total events logged: {len(events)} | Unique attacker IPs: {locations['src_ip'].nunique()} | Countries: {locations['country'].nunique()}</p>")

for fig in [fig5, fig6, fig1, fig2, fig3, fig4]:
    html_parts.append("<div class='chart'>")
    html_parts.append(fig.to_html(full_html=False, include_plotlyjs='cdn'))
    html_parts.append("</div>")

html_parts.append("<p style='text-align:center;font-size:12px;color:#888;'>Note: Source IPs represent network origin, not necessarily attacker's true location — many correspond to cloud hosting providers or VPN infrastructure.</p>")
html_parts.append("</body></html>")

with open('honeypot_dashboard.html', 'w') as f:
    f.write('\n'.join(html_parts))

print("Dashboard saved as honeypot_dashboard.html")
