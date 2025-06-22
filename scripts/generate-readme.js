#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const DATABASE_FILE = path.join(__dirname, '..', 'all.json');
const README_FILE = path.join(__dirname, '..', 'README.md');
const MAX_ENTRIES = 10; // Show latest 10 entries in README

function generateReadme() {
  console.log('📝 Generating README.md from database...');
  
  // Check if database exists
  if (!fs.existsSync(DATABASE_FILE)) {
    console.error('❌ Database file not found:', DATABASE_FILE);
    process.exit(1);
  }
  
  // Load database
  let database;
  try {
    const content = fs.readFileSync(DATABASE_FILE, 'utf8');
    database = JSON.parse(content);
  } catch (error) {
    console.error('❌ Error reading database:', error.message);
    process.exit(1);
  }
  
  // Validate database structure
  if (!database.metadata || !database.vulnerabilities) {
    console.error('❌ Invalid database structure');
    process.exit(1);
  }
  
  // Sort vulnerabilities by date (newest first)
  const sortedVulns = database.vulnerabilities.sort((a, b) => {
    const dateA = new Date(a.updated_at || a.published_at);
    const dateB = new Date(b.updated_at || b.published_at);
    return dateB - dateA;
  });
  
  // Get latest entries
  const latestEntries = sortedVulns.slice(0, MAX_ENTRIES);
  
  // Generate README content
  const readmeContent = generateReadmeContent(database, latestEntries);
  
  // Write README
  try {
    fs.writeFileSync(README_FILE, readmeContent);
    console.log('✅ README.md generated successfully!');
    console.log(`📊 Included ${latestEntries.length} latest entries`);
    console.log(`📄 Total vulnerabilities in database: ${database.vulnerabilities.length}`);
  } catch (error) {
    console.error('❌ Error writing README:', error.message);
    process.exit(1);
  }
}

function generateReadmeContent(database, latestEntries) {
  const { metadata } = database;
  const totalCount = metadata.total_count;
  const lastUpdated = new Date(metadata.last_updated).toLocaleDateString();
  const generatedAt = new Date(metadata.generated_at).toLocaleDateString();
  
  // Count by severity
  const severityCounts = database.vulnerabilities.reduce((acc, vuln) => {
    acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
    return acc;
  }, {});
  
  return `# BSVD - Baysec Vulnerability Database

## 📊 Database Statistics

- **Total Vulnerabilities**: ${totalCount}
- **Last Updated**: ${lastUpdated}
- **Generated**: ${generatedAt}

### Severity Breakdown
${Object.entries(severityCounts)
  .sort(([,a], [,b]) => b - a)
  .map(([severity, count]) => {
    const emoji = getSeverityEmoji(severity);
    return `- ${emoji} **${severity.charAt(0).toUpperCase() + severity.slice(1)}**: ${count}`;
  }).join('\n')}

## Vulnerabilities

${latestEntries.map((vuln, index) => generateVulnEntry(vuln, index + 1)).join('\n\n')}

${latestEntries.length < totalCount ? `\n**[View all ${totalCount} vulnerabilities in all.json](./all.json)**\n` : ''}
`;
}

function generateVulnEntry(vuln, index) {
  const publishedDate = new Date(vuln.published_at).toLocaleDateString();
  const updatedDate = vuln.updated_at ? new Date(vuln.updated_at).toLocaleDateString() : null;
  const severityEmoji = getSeverityEmoji(vuln.severity);
  
  // Build title with IDs
  let title = `### ${index}. ${vuln.id}`;
  if (vuln.cve_id) title += ` - ${vuln.cve_id}`;
  title += ` - ${vuln.title}`;
  
  let entry = `${title}

${severityEmoji} **${vuln.severity.toUpperCase()}** | Type: **${vuln.type.toUpperCase()}**`;

  // Add all identifiers
  const identifiers = [];
  if (vuln.cve_id) identifiers.push(`CVE: \`${vuln.cve_id}\``);
  if (vuln.euvd_id) identifiers.push(`EUVD: \`${vuln.euvd_id}\``);
  if (vuln.zdi_id) identifiers.push(`ZDI: \`${vuln.zdi_id}\``);
  if (vuln.github_advisory_id) identifiers.push(`GHSA: \`${vuln.github_advisory_id}\``);
  if (vuln.mitre_tracking_id) identifiers.push(`MITRE: \`${vuln.mitre_tracking_id}\``);
  if (vuln.cvss_score) identifiers.push(`CVSS: \`${vuln.cvss_score}\``);
  
  if (identifiers.length > 0) {
    entry += `\n\n**Identifiers:** ${identifiers.join(' | ')}`;
  }
  
  // Full description
  entry += `\n\n**Description:**\n${vuln.description}`;
  
  // Technical details
  entry += `\n\n**Technical Details:**`;
  if (vuln.cvss_vector) {
    entry += `\n- **CVSS Vector**: \`${vuln.cvss_vector}\``;
  }
  if (vuln.base_score) {
    entry += `\n- **Base Score**: ${vuln.base_score}`;
  }
  if (vuln.exploitability_score) {
    entry += `\n- **Exploitability Score**: ${vuln.exploitability_score}`;
  }
  if (vuln.impact_score) {
    entry += `\n- **Impact Score**: ${vuln.impact_score}`;
  }
  
  // Affected systems
  if (vuln.affected_vendors && vuln.affected_vendors.length > 0) {
    entry += `\n- **Affected Vendors**: ${vuln.affected_vendors.join(', ')}`;
  }
  if (vuln.affected_products && vuln.affected_products.length > 0) {
    entry += `\n- **Affected Products**: ${vuln.affected_products.join(', ')}`;
  }
  
  // MITRE information
  if (vuln.mitre_cwe_ids && vuln.mitre_cwe_ids.length > 0) {
    entry += `\n- **CWE IDs**: ${vuln.mitre_cwe_ids.join(', ')}`;
  }
  if (vuln.mitre_attack_techniques && vuln.mitre_attack_techniques.length > 0) {
    entry += `\n- **MITRE ATT&CK**: ${vuln.mitre_attack_techniques.join(', ')}`;
  }
  
  // Authors
  if (vuln.authors && vuln.authors.length > 0) {
    entry += `\n\n**Discovered by:**`;
    vuln.authors.forEach(author => {
      entry += `\n- **${author.name}**`;
      if (author.organization) entry += ` (${author.organization})`;
      if (author.email) entry += ` - ${author.email}`;
    });
  }
  
  // Fix information
  if (vuln.fix_available || vuln.fix_version || vuln.vendor_response) {
    entry += `\n\n**Fix Information:**`;
    if (vuln.fix_available) {
      entry += `\n- **Fix Available**: ${vuln.fix_available ? 'Yes' : 'No'}`;
    }
    if (vuln.fix_version) {
      entry += `\n- **Fixed in Version**: ${vuln.fix_version}`;
    }
    if (vuln.vendor_response) {
      entry += `\n- **Vendor Response**: ${vuln.vendor_response}`;
    }
  }
  
  // Proof of concept
  if (vuln.proof_of_concept) {
    entry += `\n\n**Proof of Concept:**\n${vuln.proof_of_concept}`;
  }
  
  // Disclosure timeline
  if (vuln.disclosure_timeline && vuln.disclosure_timeline.length > 0) {
    entry += `\n\n**Disclosure Timeline:**`;
    vuln.disclosure_timeline.forEach(event => {
      const eventDate = new Date(event.date).toLocaleDateString();
      entry += `\n- **${eventDate}**: ${event.event}`;
      if (event.description) {
        entry += ` - ${event.description}`;
      }
    });
  }
  
  // References
  if (vuln.reference_urls && vuln.reference_urls.length > 0) {
    entry += `\n\n**References:**`;
    vuln.reference_urls.forEach((url, idx) => {
      entry += `\n- [Reference ${idx + 1}](${url})`;
    });
  }
  
  // Tags
  if (vuln.tags && vuln.tags.length > 0) {
    entry += `\n\n**Tags:** ${vuln.tags.map(tag => `\`${tag}\``).join(', ')}`;
  }
  
  // Dates
  entry += `\n\n**Published**: ${publishedDate}`;
  if (updatedDate && updatedDate !== publishedDate) {
    entry += ` | **Updated**: ${updatedDate}`;
  }
  
  // Add file link
  entry += `\n\n[📄 View full entry](./entries/${vuln.id}.json)`;
  
  return entry;
}

function getSeverityEmoji(severity) {
  const emojis = {
    'critical': '🔴',
    'high': '🟠', 
    'medium': '🟡',
    'low': '🔵',
    'info': '⚪'
  };
  return emojis[severity] || '❓';
}

// Run the generator
generateReadme(); 