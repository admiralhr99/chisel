# Chisel Reality Testing Guide

## Quick Start

### 1. Generate Keys
```bash
./chisel genkey
# Save output:
# Private Key: xxxxx (for server)
# Public Key: yyyyy (for client)
```

### 2. Start Server (Germany VPS)
```bash
# With TLS certificate (recommended for production)
./chisel server \
  --port 443 \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem \
  --reality-privkey "YOUR_PRIVATE_KEY" \
  --reality-shortid "myid" \
  --reality-fallback "https://www.google.com" \
  --reverse \
  -v

# For testing without TLS (local network only)
./chisel server \
  --port 8080 \
  --reality-privkey "YOUR_PRIVATE_KEY" \
  --reality-shortid "myid" \
  -v
```

### 3. Start Client (Iran VPS)
```bash
# With TLS
./chisel client \
  --reality-pubkey "YOUR_PUBLIC_KEY" \
  --reality-shortid "myid" \
  wss://germany-server:443 \
  socks \
  -v

# Without TLS (local testing)
./chisel client \
  --reality-pubkey "YOUR_PUBLIC_KEY" \
  --reality-shortid "myid" \
  ws://server:8080 \
  socks \
  -v
```

---

## Testing Methodology

### Test Categories

| Test | What it Measures | Tools |
|------|------------------|-------|
| Latency | Round-trip time | ping, curl, custom scripts |
| Throughput | Bandwidth (Mbps) | iperf3, speedtest-cli |
| Stability | Connection drops, errors | long-running tests |
| Jitter | Latency variance | ping statistics |

---

## Local Network Testing

### Setup (Two machines or Docker)

**Machine A (Server):**
```bash
./chisel genkey  # Save keys

# Normal chisel (baseline)
./chisel server --port 8080 -v

# Reality chisel
./chisel server --port 8081 \
  --reality-privkey "PRIVKEY" \
  --reality-shortid "test" \
  -v
```

**Machine B (Client):**
```bash
# Connect to normal chisel
./chisel client ws://serverip:8080 8888:localhost:5201 -v

# Connect to Reality chisel
./chisel client \
  --reality-pubkey "PUBKEY" \
  --reality-shortid "test" \
  ws://serverip:8081 \
  8889:localhost:5201 \
  -v
```

---

## Test 1: Latency Test

### Using curl (HTTP latency)
```bash
# Start a simple HTTP server on the server side
python3 -m http.server 5000

# On server, forward port through tunnel
# Client connects: 8888:localhost:5000

# Test latency
for i in {1..100}; do
  curl -o /dev/null -s -w "%{time_total}\n" http://localhost:8888/
done | awk '{sum+=$1; count++} END {print "Avg: " sum/count*1000 " ms"}'
```

### Using custom script
```bash
#!/bin/bash
# latency-test.sh
HOST=${1:-localhost}
PORT=${2:-8888}
COUNT=${3:-100}

echo "Testing latency to $HOST:$PORT ($COUNT requests)..."

times=()
for i in $(seq 1 $COUNT); do
  start=$(date +%s%N)
  nc -z -w1 $HOST $PORT 2>/dev/null
  end=$(date +%s%N)
  elapsed=$(( (end - start) / 1000000 ))
  times+=($elapsed)
  echo -ne "\rProgress: $i/$COUNT"
done

echo ""
echo "Results:"
printf '%s\n' "${times[@]}" | awk '
{
  sum += $1
  sumsq += $1^2
  if (NR == 1 || $1 < min) min = $1
  if (NR == 1 || $1 > max) max = $1
  a[NR] = $1
}
END {
  avg = sum/NR
  std = sqrt(sumsq/NR - avg^2)
  print "Min: " min " ms"
  print "Max: " max " ms"
  print "Avg: " avg " ms"
  print "Std: " std " ms"
}'
```

---

## Test 2: Throughput Test (iperf3)

### Setup
```bash
# Install iperf3 on both machines
apt install iperf3  # Debian/Ubuntu
yum install iperf3  # CentOS/RHEL
```

### Server Side
```bash
# Start iperf3 server
iperf3 -s -p 5201
```

### Client Side (through tunnel)
```bash
# Forward iperf port through chisel
# Assuming client is connected with: 5201:localhost:5201

# Run throughput test
iperf3 -c localhost -p 5201 -t 30 -P 4

# Options:
#   -t 30    : Run for 30 seconds
#   -P 4     : Use 4 parallel streams
#   -R       : Reverse mode (server sends to client)
```

### Comprehensive iperf3 Test Script
```bash
#!/bin/bash
# throughput-test.sh

SERVER=${1:-localhost}
PORT=${2:-5201}
DURATION=${3:-30}

echo "=== Throughput Test ==="
echo "Server: $SERVER:$PORT"
echo "Duration: ${DURATION}s"
echo ""

echo "--- Download Test (Server → Client) ---"
iperf3 -c $SERVER -p $PORT -t $DURATION -R

echo ""
echo "--- Upload Test (Client → Server) ---"
iperf3 -c $SERVER -p $PORT -t $DURATION

echo ""
echo "--- Bidirectional Test ---"
iperf3 -c $SERVER -p $PORT -t $DURATION --bidir
```

---

## Test 3: Stability Test (Long-running)

### Connection Stability Script
```bash
#!/bin/bash
# stability-test.sh

HOST=${1:-localhost}
PORT=${2:-8888}
DURATION=${3:-3600}  # 1 hour default
INTERVAL=${4:-5}     # Check every 5 seconds

echo "=== Stability Test ==="
echo "Target: $HOST:$PORT"
echo "Duration: ${DURATION}s"
echo "Interval: ${INTERVAL}s"
echo ""

start_time=$(date +%s)
end_time=$((start_time + DURATION))
success=0
failure=0
total=0

while [ $(date +%s) -lt $end_time ]; do
  total=$((total + 1))

  if nc -z -w2 $HOST $PORT 2>/dev/null; then
    success=$((success + 1))
    status="OK"
  else
    failure=$((failure + 1))
    status="FAIL"
  fi

  elapsed=$(($(date +%s) - start_time))
  uptime_pct=$(echo "scale=2; $success * 100 / $total" | bc)

  echo "[$(date '+%H:%M:%S')] $status | Success: $success | Fail: $failure | Uptime: ${uptime_pct}%"

  sleep $INTERVAL
done

echo ""
echo "=== Final Results ==="
echo "Total checks: $total"
echo "Successful: $success"
echo "Failed: $failure"
echo "Uptime: ${uptime_pct}%"
```

---

## Test 4: Comparison Test (Normal vs Reality)

### Automated Comparison Script
```bash
#!/bin/bash
# compare-chisel.sh
# Compare normal chisel vs Reality chisel

NORMAL_PORT=8888    # Port forwarded through normal chisel
REALITY_PORT=8889   # Port forwarded through Reality chisel
IPERF_PORT=5201
TEST_DURATION=30

echo "============================================"
echo "  Chisel vs Reality Chisel Comparison Test"
echo "============================================"
echo ""

# Function to run latency test
test_latency() {
  local port=$1
  local name=$2
  echo "Testing latency for $name (port $port)..."

  for i in {1..50}; do
    start=$(date +%s%N)
    nc -z -w1 localhost $port 2>/dev/null
    end=$(date +%s%N)
    echo $(( (end - start) / 1000000 ))
  done | awk -v name="$name" '
  {
    sum += $1
    if (NR == 1 || $1 < min) min = $1
    if (NR == 1 || $1 > max) max = $1
  }
  END {
    print name ": min=" min "ms, max=" max "ms, avg=" sum/NR "ms"
  }'
}

# Function to run throughput test
test_throughput() {
  local port=$1
  local name=$2
  echo ""
  echo "Testing throughput for $name (port $port)..."
  iperf3 -c localhost -p $port -t $TEST_DURATION -J | \
    jq -r '.end.sum_received.bits_per_second / 1000000 | "'"$name"': \(.) Mbps"'
}

echo "=== LATENCY TEST ==="
test_latency $NORMAL_PORT "Normal Chisel"
test_latency $REALITY_PORT "Reality Chisel"

echo ""
echo "=== THROUGHPUT TEST ==="
test_throughput $NORMAL_PORT "Normal Chisel"
test_throughput $REALITY_PORT "Reality Chisel"

echo ""
echo "============================================"
echo "  Test Complete"
echo "============================================"
```

---

## Iran ↔ Germany VPS Testing

### Network Setup Diagram
```
[Iran VPS] ←── Chisel Tunnel ──→ [Germany VPS] ←── Internet ──→ [Target]
   Client                            Server
```

### Step-by-Step Setup

**1. On Germany VPS (Server):**
```bash
# Generate keys
./chisel genkey
# Private: ABC123...
# Public: XYZ789...

# Get TLS certificate (using Let's Encrypt)
certbot certonly --standalone -d your-domain.com

# Start server with Reality
./chisel server \
  --port 443 \
  --tls-cert /etc/letsencrypt/live/your-domain.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/your-domain.com/privkey.pem \
  --reality-privkey "ABC123..." \
  --reality-shortid "iran-user" \
  --reality-fallback "https://www.google.com" \
  --reverse \
  --socks5 \
  -v

# Also start iperf3 for testing
iperf3 -s -p 5201 &
```

**2. On Iran VPS (Client):**
```bash
# Connect with Reality
./chisel client \
  --reality-pubkey "XYZ789..." \
  --reality-shortid "iran-user" \
  wss://your-domain.com:443 \
  1080:socks \
  5201:localhost:5201 \
  -v
```

**3. Run Tests from Iran VPS:**
```bash
# Latency test
ping -c 100 localhost | tail -1

# Throughput test
iperf3 -c localhost -p 5201 -t 60

# HTTP latency through SOCKS
curl -x socks5://localhost:1080 \
  -o /dev/null -s -w "Total: %{time_total}s\n" \
  https://www.google.com

# Stability test
./stability-test.sh localhost 1080 3600 10
```

---

## Benchmark Results Template

### Record your results:

```markdown
## Test Environment
- Date: YYYY-MM-DD
- Iran VPS: [Provider], [Location], [CPU], [RAM]
- Germany VPS: [Provider], [Location], [CPU], [RAM]
- Network: [ISP info]

## Latency Results (ms)
| Mode | Min | Max | Avg | Std Dev |
|------|-----|-----|-----|---------|
| Direct (no tunnel) | | | | |
| Normal Chisel | | | | |
| Reality Chisel | | | | |

## Throughput Results (Mbps)
| Mode | Download | Upload | Bidirectional |
|------|----------|--------|---------------|
| Direct (no tunnel) | | | |
| Normal Chisel | | | |
| Reality Chisel | | | |

## Stability Results (1 hour test)
| Mode | Uptime % | Disconnections | Avg Reconnect Time |
|------|----------|----------------|-------------------|
| Normal Chisel | | | |
| Reality Chisel | | | |

## Observations
- Reality overhead: ~X ms additional latency
- Throughput difference: ~Y%
- Stability notes: ...
```

---

## Expected Results

### Typical Overhead
- **Latency**: Reality adds ~1-5ms overhead (crypto operations)
- **Throughput**: ~5-10% reduction due to uTLS + encryption
- **Stability**: Should be identical or better (anti-probing helps avoid blocks)

### Red Flags
- Latency > 50ms overhead → Check server CPU
- Throughput < 50% of direct → Check network path
- Frequent disconnections → Check firewall/DPI blocking

---

## Troubleshooting

### Connection Fails
```bash
# Test without Reality first
./chisel client ws://server:8080 8888:localhost:80 -v

# Check if port is open
nc -zv server 443

# Check TLS certificate
openssl s_client -connect server:443
```

### High Latency
```bash
# Check MTU issues
ping -M do -s 1472 server

# Trace route
traceroute server
mtr server
```

### Throughput Issues
```bash
# Check for packet loss
ping -c 1000 server | grep loss

# Check TCP window scaling
sysctl net.ipv4.tcp_window_scaling
```
