/**
 * Binary Data Parsing in n8n Code Nodes
 *
 * Demonstrates the correct way to access binary data from n8n's
 * readWriteFile node output. Fixed in v6.3 (2025-12-11).
 *
 * Node: "Generate Final Report" in Phase 3 Manager workflow
 */

// ============================================================================
// WRONG (v6.2) - This caused the JSONL parsing bug
// ============================================================================

// This approach assumes the property name is always "data"
const jsonlContent = Buffer.from(fileData.data.data, 'base64').toString('utf-8');

// Problem: n8n binary objects use dynamic property names, not always "data"
// Result: Crashes or returns undefined


// ============================================================================
// CORRECT (v6.3) - Dynamic property name extraction
// ============================================================================

const binaryObj = $input.item.binary;

// Get the actual property name (could be "data", "file", or anything)
const propName = Object.keys(binaryObj)[0];

// Access the binary data using the dynamic property name
const jsonlContent = Buffer.from(binaryObj[propName].data, 'base64').toString('utf-8');

// This works regardless of the property name


// ============================================================================
// Complete Example: Parse JSONL File from n8n Binary Object
// ============================================================================

// Input: n8n binary object from Read/Write Binary File node
// Output: Array of parsed JSON objects

function parseJSONLFromBinary($input) {
  const binaryObj = $input.item.binary;

  if (!binaryObj || Object.keys(binaryObj).length === 0) {
    return [];
  }

  // Get the property name dynamically
  const propName = Object.keys(binaryObj)[0];

  // Decode base64 to UTF-8 string
  const jsonlContent = Buffer.from(binaryObj[propName].data, 'base64').toString('utf-8');

  // Split into lines
  const lines = jsonlContent.split('\n').filter(line => line.trim());

  // Parse each line as JSON
  const findings = [];
  let parseErrors = 0;
  let skipped = 0;

  for (const line of lines) {
    try {
      const finding = JSON.parse(line);

      // Validate finding has required fields
      if (finding.info && finding.host) {
        findings.push(finding);
      } else {
        skipped++;
      }
    } catch (e) {
      parseErrors++;
      console.error(`Parse error: ${e.message}`);
    }
  }

  // Log statistics
  console.log(`Processing Stats:`);
  console.log(`  - Raw lines: ${lines.length}`);
  console.log(`  - Findings extracted: ${findings.length}`);
  console.log(`  - Parse errors: ${parseErrors}`);
  console.log(`  - Skipped (no info/host): ${skipped}`);

  return findings;
}

// Usage in n8n Code Node
const findings = parseJSONLFromBinary($input);
return findings;


// ============================================================================
// n8n Binary Object Structure (Reference)
// ============================================================================

/*
n8n's readWriteFile node outputs binary data in this format:

$input.item.binary = {
  "data": {                          // <-- Property name (dynamic!)
    "data": "base64encodedstring",   // <-- Actual base64 content
    "mimeType": "text/plain",        // Content type
    "fileName": "file.txt",          // Original filename
    "fileExtension": "txt",          // Extension
    "directory": "/path/to/dir"      // Directory path
  }
}

The outer "data" property name is NOT guaranteed to be "data".
It could be:
- "data"
- "file"
- "binaryData"
- Or any custom name

Always use Object.keys(binaryObj)[0] to get it dynamically!
*/


// ============================================================================
// Debug Helper: Inspect Binary Object Structure
// ============================================================================

function debugBinaryObject($input) {
  const binaryObj = $input.item.binary;

  console.log('=== Binary Object Debug ===');
  console.log('Property names:', Object.keys(binaryObj));

  for (const [key, value] of Object.entries(binaryObj)) {
    console.log(`\nProperty: ${key}`);
    console.log(`  - mimeType: ${value.mimeType}`);
    console.log(`  - fileName: ${value.fileName}`);
    console.log(`  - data length: ${value.data ? value.data.length : 0} chars`);

    if (value.data) {
      const decoded = Buffer.from(value.data, 'base64').toString('utf-8');
      console.log(`  - decoded size: ${decoded.length} bytes`);
      console.log(`  - first 100 chars: ${decoded.substring(0, 100)}`);
    }
  }
}

// Use this in a Code node to understand your binary data structure
debugBinaryObject($input);
