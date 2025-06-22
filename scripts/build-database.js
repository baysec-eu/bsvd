#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const ENTRIES_DIR = path.join(__dirname, '..', 'entries');
const OUTPUT_FILE = path.join(__dirname, '..', 'all.json');

function buildDatabase() {
  console.log('🔨 Building BSVD database...');
  
  // Check if entries directory exists
  if (!fs.existsSync(ENTRIES_DIR)) {
    console.error('❌ Entries directory not found:', ENTRIES_DIR);
    process.exit(1);
  }
  
  // Read all JSON files from entries directory
  const entryFiles = fs.readdirSync(ENTRIES_DIR)
    .filter(file => file.endsWith('.json'))
    .sort();
  
  if (entryFiles.length === 0) {
    console.log('⚠️  No entries found in entries directory');
    
    // Create empty database structure
    const emptyDatabase = {
      metadata: {
        version: "1.0.0",
        generated_at: new Date().toISOString(),
        last_updated: new Date().toISOString(),
        total_count: 0,
        sources: [],
        repository: "BAYSEC/bsvd",
        format: "BSVD"
      },
      vulnerabilities: []
    };
    
    try {
      fs.writeFileSync(OUTPUT_FILE, JSON.stringify(emptyDatabase, null, 2));
      console.log('✅ Empty database created successfully');
      return;
    } catch (error) {
      console.error('❌ Error creating empty database:', error.message);
      process.exit(1);
    }
  }
  
  console.log(`📄 Found ${entryFiles.length} entries:`);
  entryFiles.forEach(file => console.log(`   - ${file}`));
  
  // Parse all entries
  const vulnerabilities = [];
  const sources = new Set();
  let latestUpdate = null;
  
  for (const file of entryFiles) {
    try {
      const filePath = path.join(ENTRIES_DIR, file);
      const content = fs.readFileSync(filePath, 'utf8');
      const entry = JSON.parse(content);
      
      // Validate required fields
      if (!entry.id || !entry.title || !entry.description) {
        console.error(`❌ Invalid entry in ${file}: missing required fields (id, title, description)`);
        process.exit(1);
      }
      
      // Track sources
      if (entry.authors) {
        entry.authors.forEach(author => {
          if (author.organization) {
            sources.add(author.organization);
          }
        });
      }
      
      // Track latest update
      const updateTime = new Date(entry.updated_at || entry.published_at);
      if (!latestUpdate || updateTime > latestUpdate) {
        latestUpdate = updateTime;
      }
      
      vulnerabilities.push(entry);
      console.log(`   ✅ Loaded ${entry.id}: ${entry.title}`);
      
    } catch (error) {
      console.error(`❌ Error parsing ${file}:`, error.message);
      process.exit(1);
    }
  }
  
  // Sort vulnerabilities by ID
  vulnerabilities.sort((a, b) => a.id.localeCompare(b.id));
  
  // Create database structure
  const database = {
    metadata: {
      version: "1.0.0",
      generated_at: new Date().toISOString(),
      last_updated: latestUpdate ? latestUpdate.toISOString() : new Date().toISOString(),
      total_count: vulnerabilities.length,
      sources: Array.from(sources).sort(),
      repository: "BAYSEC/bsvd",
      format: "BSVD"
    },
    vulnerabilities: vulnerabilities
  };
  
  // Write all.json
  try {
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(database, null, 2));
    console.log(`✅ Database built successfully!`);
    console.log(`📊 Statistics:`);
    console.log(`   - Total vulnerabilities: ${vulnerabilities.length}`);
    console.log(`   - Sources: ${Array.from(sources).join(', ')}`);
    console.log(`   - Last updated: ${database.metadata.last_updated}`);
    console.log(`   - Output file: ${path.relative(process.cwd(), OUTPUT_FILE)}`);
    
    // Display severity breakdown
    const severityBreakdown = vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    }, {});
    
    console.log(`   - Severity breakdown:`);
    Object.entries(severityBreakdown)
      .sort(([,a], [,b]) => b - a)
      .forEach(([severity, count]) => {
        console.log(`     * ${severity}: ${count}`);
      });
    
  } catch (error) {
    console.error('❌ Error writing all.json:', error.message);
    process.exit(1);
  }
}

// Run the build
buildDatabase(); 