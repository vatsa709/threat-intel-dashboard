from flask import Flask, render_template, jsonify, request
import sqlite3
import json
from datetime import datetime, timedelta
import os

app = Flask(__name__)

def get_db_connection():
    """Get database connection"""
    try:
        conn = sqlite3.connect('threat_intelligence.db')
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def get_table_info():
    """Get information about available tables and columns"""
    conn = get_db_connection()
    if not conn:
        return {}
    
    try:
        # Get all tables
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_info = {}
        
        for table in tables:
            table_name = table['name']
            # Get column info for each table
            columns = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
            table_info[table_name] = [col['name'] for col in columns]
            
        conn.close()
        return table_info
    except Exception as e:
        print(f"Error getting table info: {e}")
        conn.close()
        return {}

def get_dashboard_data():
    """Get all dashboard data - adapted to work with any database structure"""
    conn = get_db_connection()
    if not conn:
        return {'error': 'Database connection failed'}
    
    try:
        # Get table information first
        table_info = get_table_info()
        print(f"Available tables: {list(table_info.keys())}")
        
        data = {
            'vulnerabilities': [],
            'critical_vulnerabilities': [],
            'iocs': [],
            'threat_actors': [],
            'sources': [],
            'timeline': [],
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'table_info': table_info
        }
        
        # Try to get vulnerabilities data
        if 'vulnerabilities' in table_info:
            vuln_columns = table_info['vulnerabilities']
            print(f"Vulnerability columns: {vuln_columns}")
            
            # Basic vulnerability count
            try:
                vuln_count = conn.execute("SELECT COUNT(*) as count FROM vulnerabilities").fetchone()
                data['total_vulnerabilities'] = vuln_count['count'] if vuln_count else 0
                
                # Get recent vulnerabilities
                recent_vulns = conn.execute("""
                    SELECT * FROM vulnerabilities 
                    ORDER BY rowid DESC 
                    LIMIT 10
                """).fetchall()
                
                data['critical_vulnerabilities'] = [dict(row) for row in recent_vulns]
                
                # Try to get vulnerability stats by severity if column exists
                if 'severity' in vuln_columns:
                    severity_stats = conn.execute("""
                        SELECT severity, COUNT(*) as count 
                        FROM vulnerabilities 
                        GROUP BY severity
                    """).fetchall()
                    data['vulnerabilities'] = [dict(row) for row in severity_stats]
                else:
                    # If no severity column, create a general stat
                    data['vulnerabilities'] = [{'severity': 'ALL', 'count': data['total_vulnerabilities'], 'avg_cvss': 0}]
                    
            except Exception as e:
                print(f"Error querying vulnerabilities: {e}")
        
        # Try to get IOCs data - FIXED: Changed 'type' to 'ioc_type'
        if 'iocs' in table_info:
            try:
                ioc_stats = conn.execute("""
                    SELECT ioc_type, COUNT(*) as count, AVG(CAST(confidence as FLOAT)) as avg_confidence
                    FROM iocs 
                    GROUP BY ioc_type
                    ORDER BY count DESC
                """).fetchall()
                data['iocs'] = [dict(row) for row in ioc_stats]
            except Exception as e:
                print(f"Error querying IOCs: {e}")
                # Try without confidence column
                try:
                    ioc_stats = conn.execute("""
                        SELECT ioc_type, COUNT(*) as count, 75 as avg_confidence
                        FROM iocs 
                        GROUP BY ioc_type
                        ORDER BY count DESC
                    """).fetchall()
                    data['iocs'] = [dict(row) for row in ioc_stats]
                except Exception as e2:
                    print(f"Error querying IOCs (fallback): {e2}")
        
        # Try to get threat actors - FIXED: Changed 'threat_reports' to 'threat_intel'
        if 'threat_intel' in table_info:
            try:
                threat_actors = conn.execute("""
                    SELECT threat_actor, COUNT(*) as report_count
                    FROM threat_intel 
                    WHERE threat_actor IS NOT NULL AND threat_actor != ''
                    GROUP BY threat_actor
                    ORDER BY report_count DESC
                    LIMIT 10
                """).fetchall()
                data['threat_actors'] = [dict(row) for row in threat_actors]
            except Exception as e:
                print(f"Error querying threat actors: {e}")
        
        # Get data sources from all tables
        sources_data = []
        for table_name in table_info.keys():
            if 'source' in table_info[table_name]:
                try:
                    source_stats = conn.execute(f"""
                        SELECT source, COUNT(*) as entry_count
                        FROM {table_name}
                        WHERE source IS NOT NULL AND source != ''
                        GROUP BY source
                    """).fetchall()
                    sources_data.extend([dict(row) for row in source_stats])
                except Exception as e:
                    print(f"Error querying sources from {table_name}: {e}")
        
        # Combine sources
        source_summary = {}
        for source in sources_data:
            source_name = source['source']
            if source_name in source_summary:
                source_summary[source_name] += source['entry_count']
            else:
                source_summary[source_name] = source['entry_count']
        
        data['sources'] = [{'source': k, 'entry_count': v} for k, v in source_summary.items()]
        
        conn.close()
        return data
        
    except Exception as e:
        print(f"Error in get_dashboard_data: {e}")
        conn.close()
        return {'error': str(e)}

@app.route('/')
def dashboard():
    """Main dashboard route"""
    return render_template('dashboard.html')

@app.route('/api/dashboard-data')
def api_dashboard_data():
    """API endpoint for dashboard data"""
    try:
        data = get_dashboard_data()
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug')
def api_debug():
    """Debug endpoint to check database structure"""
    table_info = get_table_info()
    return jsonify(table_info)

@app.route('/api/vulnerabilities')
def api_vulnerabilities():
    """API endpoint for vulnerabilities"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        
        offset = (page - 1) * per_page
        
        vulns = conn.execute("""
            SELECT * FROM vulnerabilities 
            ORDER BY rowid DESC 
            LIMIT ? OFFSET ?
        """, (per_page, offset)).fetchall()
        
        total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'vulnerabilities': [dict(row) for row in vulns],
            'total': total,
            'page': page,
            'per_page': per_page
        })
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/api/iocs')
def api_iocs():
    """API endpoint for IOCs"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        
        offset = (page - 1) * per_page
        
        iocs = conn.execute("""
            SELECT * FROM iocs 
            ORDER BY rowid DESC 
            LIMIT ? OFFSET ?
        """, (per_page, offset)).fetchall()
        
        total = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'iocs': [dict(row) for row in iocs],
            'total': total,
            'page': page,
            'per_page': per_page
        })
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    if not os.path.exists('templates'):
        os.makedirs('templates')
    if not os.path.exists('static'):
        os.makedirs('static')
    
    print("Starting Threat Intelligence Dashboard...")
    print("Debug endpoint available at: http://localhost:5000/api/debug")
    
    app.run(debug=True, host='0.0.0.0', port=5000)