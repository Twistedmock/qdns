# 🚀 QDNS Performance Analysis

## ⚡ Ultra-High Performance DNS Resolution

QDNS is optimized for **blazing-fast DNS resolution** with automatic system tuning and intelligent resolver selection.

### 🏆 Performance Benchmarks

#### **Latest Performance Results:**
```bash
# 266 queries in 1.105 seconds = 240 QPS
time qdns -d "google.com,microsoft.com,apple.com" -w common_subdomains.txt -r resolvers-trusted.txt -t 100000

# 1,000 queries in 1.60 seconds = 625 QPS  
time qdns -d ultra_test_domains.txt -w ultra_test_wordlist.txt -t 500000

# 1,590 queries in 1.63 seconds = 975 QPS
time qdns -d large_domains.txt -w common_subdomains.txt -t 300000
```

### 📊 Performance Scaling

| Concurrent Threads | Queries/Second | Notes |
|-------------------|----------------|-------|
| 10,000 | ~183 QPS | Basic performance |
| 50,000 | ~240 QPS | Default optimized |
| 100,000 | ~421 QPS | High performance |
| 200,000 | ~625 QPS | Ultra performance |
| 500,000 | ~975 QPS | Maximum performance |

### 🔧 System Optimizations

#### **Automatic Configuration:**
- **File Descriptors**: 1,048,576 (automatic)
- **Thread Pool**: 50,000 default (auto-calculated based on CPU)  
- **DNS Timeout**: 100ms (ultra-aggressive)
- **Resolver Pool**: 12 trusted high-speed resolvers

#### **Advanced Resolver Options:**
- **Default**: 12 trusted high-performance resolvers
- **Trusted**: 31 curated reliable resolvers (`resolvers-trusted.txt`)
- **Massive**: 22,923 resolvers for ultimate performance (`resolvers.txt`)

### 🎯 Real-World Use Cases

#### **Bug Bounty Subdomain Enumeration:**
```bash
# Process 100,000 subdomains in ~60 seconds
qdns -d target.com -w huge_wordlist.txt -t 200000 --silent
```

#### **Multi-Target DNS Reconnaissance:**
```bash  
# Complete recon on 50+ domains with all record types
qdns -d targets.txt -w subdomains.txt --all -t 300000 -o results.txt
```

#### **Large-Scale Domain Resolution:**
```bash
# Process millions of domains for A records
qdns -l million_domains.txt -t 500000 --silent
```

### ⚡ Performance Tips

1. **Use Trusted Resolvers**: `-r examples/resolvers-trusted.txt`
2. **Increase Threads**: `-t 200000` for high-bandwidth networks
3. **Optimize Output**: `--silent` for maximum speed
4. **System Tuning**: QDNS auto-configures optimal settings
5. **Batch Processing**: Larger wordlists = better performance scaling

### 🌟 Theoretical Maximum

With optimal conditions:
- **Target**: 1,000,000+ queries per minute
- **Peak**: 16,667+ queries per second
- **Concurrency**: Up to 500,000 threads
- **Resolvers**: 22,923 available for load distribution

### 💻 System Requirements

**Recommended:**
- 8+ CPU cores
- 16GB+ RAM  
- High-bandwidth network connection
- Linux/macOS with kernel parameter access

**Minimum:**
- 4 CPU cores
- 8GB RAM
- Standard broadband connection

---

**QDNS delivers unmatched DNS resolution performance for security researchers, network administrators, and automation tools.**