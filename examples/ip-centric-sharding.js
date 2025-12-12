/**
 * IP-Centric Sharding Algorithm
 *
 * Used in Phase 3 Manager to distribute hosts across 5 workers
 * based on IP address clustering. This prevents WAF blocks by ensuring
 * hosts on the same IP are always scanned by the same worker.
 *
 * Node: "IP-Centric Sharding" in Phase 3 Manager workflow
 */

const hosts = $input.all();
const workerCount = 5;
const timestamp = new Date().getTime();

// Initialize worker buckets
const workers = Array.from({ length: workerCount }, (_, i) => ({
  workerIndex: i + 1,
  timestamp: timestamp,
  targets: [],
  ipClusters: new Map()
}));

// Process each host
for (const hostItem of hosts) {
  const host = hostItem.json;

  // Extract IP with multiple field fallbacks
  // IMPORTANT: Phase 2 uses 'ip_addresses' field!
  let ip = host.ip_addresses || host.ip || host.resolved_ip || host.a || 'unknown';

  // Handle array of IPs (take first)
  if (Array.isArray(ip)) {
    ip = ip[0] || 'unknown';
  }

  // Normalize - handle comma-separated IPs
  ip = String(ip).trim();
  if (ip.includes(',')) {
    ip = ip.split(',')[0].trim();
  }

  // Find if this IP is already assigned to a worker
  let assignedWorker = null;
  for (const worker of workers) {
    if (worker.ipClusters.has(ip)) {
      assignedWorker = worker;
      break;
    }
  }

  // If not assigned, use round-robin to find worker with least hosts
  if (!assignedWorker) {
    assignedWorker = workers.reduce((min, worker) =>
      worker.targets.length < min.targets.length ? worker : min
    );

    // Mark this IP as assigned to this worker
    assignedWorker.ipClusters.set(ip, true);
  }

  // Add host to worker's target list
  assignedWorker.targets.push({
    url: host.url || host.host,
    ip: ip,
    tech: host.tech || []
  });
}

// Convert ipClusters Map to regular object for output
const output = workers.map(worker => ({
  workerIndex: worker.workerIndex,
  timestamp: worker.timestamp,
  targets: worker.targets,
  hostCount: worker.targets.length,
  ipCount: worker.ipClusters.size
}));

return output;
