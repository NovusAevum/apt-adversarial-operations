_threats = cursor.fetchall()
        
        conn.close()
        
        # Generate report
        report = {
            'operation': self.operation_name,
            'generated': datetime.now().isoformat(),
            'summary': {
                'total_targets_identified': total_targets,
                'average_threat_score': round(avg_threat, 2),
                'high_threat_targets': high_threat_targets,
                'intelligence_sources': self.count_sources()
            },
            'top_priority_targets': [
                {
                    'id': t[0],
                    'name': t[1],
                    'type': t[2],
                    'threat_score': t[3],
                    'classification': self.classify_threat_level(t[3])
                }
                for t in top_threats
            ],
            'recommendations': self.generate_recommendations()
        }
        
        # Write to file
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[REPORT] Intelligence report exported to: {output_file}")
        print(f"  Total Targets: {total_targets}")
        print(f"  High-Threat Targets: {high_threat_targets}")
        print(f"  Average Threat Score: {avg_threat:.1f}/100")
    
    def count_sources(self) -> Dict:
        """Count intelligence sources by type"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source_type, COUNT(*) 
            FROM intelligence_sources 
            GROUP BY source_type
        ''')
        
        sources = dict(cursor.fetchall())
        conn.close()
        
        return sources
    
    def generate_recommendations(self) -> List[str]:
        """
        AI-generated operational recommendations
        Based on intelligence gathered
        """
        recommendations = [
            "Prioritize high-threat targets for detailed analysis",
            "Establish continuous monitoring of identified infrastructure",
            "Conduct social engineering assessment of human targets",
            "Map trust relationships for lateral movement opportunities",
            "Identify supply chain vulnerabilities in organizational targets",
            "Assess cloud infrastructure exposure",
            "Correlate with CVE databases for known vulnerabilities"
        ]
        
        return recommendations


# Demonstration usage
if __name__ == "__main__":
    print("="*70)
    print("Advanced AI-Powered Reconnaissance & Target Intelligence System")
    print("="*70)
    
    # Initialize system
    airtis = AIReconnaissanceSystem("DEMO_OPERATION")
    
    # Simulate OSINT data ingestion
    print("\n[DEMO] Ingesting sample OSINT data...")
    
    sample_osint = [
        {
            'source': 'LinkedIn',
            'text': 'John Smith, Security Admin at TechCorp Inc. Email: j.smith@techcorp.com',
            'location': 'San Francisco, CA'
        },
        {
            'source': 'DNS Records',
            'text': 'Domain: techcorp.com resolves to 192.168.1.100. Mail server: mail.techcorp.com',
            'location': 'Cloud Infrastructure'
        },
        {
            'source': 'GitHub',
            'text': 'Repository: techcorp/infrastructure contains AWS configuration files. Admin contact: admin@techcorp.com',
            'location': 'Public Repository'
        }
    ]
    
    for data in sample_osint:
        airtis.ingest_osint_data(data['source'], data)
    
    # Map relationships
    airtis.map_relationships()
    
    # Generate report
    print("\n[DEMO] Generating intelligence report...")
    airtis.export_intelligence_report("intelligence_report.json")
    
    print("\n[DEMO] System demonstration complete")
    print("\n" + "="*70)
    print("OPERATIONAL NOTE:")
    print("This tool demonstrates AI-driven reconnaissance principles used by")
    print("state-sponsored actors for target identification and prioritization.")
    print("Actual nation-state systems process petabytes of data with advanced")
    print("ML models for facial recognition, behavioral analysis, and predictive")
    print("targeting as documented in Israeli Gospel/Lavender systems.")
    print("="*70)
