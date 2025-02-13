import time
from datetime import datetime
from collections import defaultdict
import numpy as np
from typing import Dict, List, Tuple
import logging
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

class DDoSDetector:
    def __init__(self):
        # Configuration parameters
        self.TIME_WINDOW = 300  # 5 minutes in seconds
        self.REQUEST_THRESHOLD = 1000  # Max requests per IP in time window
        self.SUSPICIOUS_STATUS_CODES = {400, 401, 403, 404, 500}
        self.UNUSUAL_HOURS = set(range(0, 6))  # 12AM to 6AM
        
        # Tracking dictionaries
        self.ip_requests: Dict[str, List[float]] = defaultdict(list)
        self.endpoint_requests: Dict[str, List[float]] = defaultdict(list)
        self.status_codes: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self.behavioral_profiles: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("DDoSDetector")

        # Initialize InfluxDB client for real-time monitoring
        self.client = InfluxDBClient(
            url="http://localhost:8086",
            token="your-token",
            org="your-org"
        )
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)

    def analyze_request(self, request_data: dict) -> Tuple[bool, str]:
        """
        Analyzes a single request for DDoS indicators.
        Returns (is_attack: bool, attack_type: str)
        """
        current_time = time.time()
        ip = request_data['ip']
        endpoint = request_data['endpoint']
        status_code = request_data['status_code']
        user_agent = request_data['user_agent']
        
        # Clean old requests outside time window
        self._clean_old_requests(current_time)
        
        # Record request data
        self.ip_requests[ip].append(current_time)
        self.endpoint_requests[endpoint].append(current_time)
        self.status_codes[ip][status_code] += 1
        self.behavioral_profiles[ip][user_agent] += 1
        
        # Log metrics to InfluxDB
        self.record_metrics("request_count", 1, {"ip": ip, "endpoint": endpoint})

        # Check for attack indicators
        indicators = []
        
        # 1. Check request rate from single IP
        if len(self.ip_requests[ip]) > self.REQUEST_THRESHOLD:
            indicators.append("High request rate from single IP")
        
        # 2. Check for behavioral profile anomalies
        if self._check_behavioral_anomaly(ip):
            indicators.append("Suspicious behavioral profile")
        
        # 3. Check for endpoint flooding
        if self._check_endpoint_flooding(endpoint):
            indicators.append("Endpoint flooding detected")
        
        # 4. Check for unusual timing patterns
        if self._check_unusual_timing(current_time):
            indicators.append("Unusual timing pattern")
        
        # 5. Check for high error rates
        if self._check_error_rate(ip):
            indicators.append("High error rate")
        
        is_attack = len(indicators) >= 2  # Require multiple indicators for attack classification
        attack_type = " & ".join(indicators) if is_attack else "None"
        
        if is_attack:
            self.logger.warning(f"DDoS attack detected from IP {ip}: {attack_type}")
            
        return is_attack, attack_type

    def _clean_old_requests(self, current_time: float) -> None:
        """Remove requests outside the time window"""
        cutoff_time = current_time - self.TIME_WINDOW
        
        for ip in list(self.ip_requests.keys()):
            self.ip_requests[ip] = [t for t in self.ip_requests[ip] if t > cutoff_time]
            
        for endpoint in list(self.endpoint_requests.keys()):
            self.endpoint_requests[endpoint] = [t for t in self.endpoint_requests[endpoint] if t > cutoff_time]

    def _check_behavioral_anomaly(self, ip: str) -> bool:
        """Check if requests from an IP show suspicious behavioral patterns"""
        profiles = self.behavioral_profiles[ip]
        if not profiles:
            return False
            
        # Check if too many requests use the same exact profile
        total_requests = sum(profiles.values())
        max_profile_requests = max(profiles.values())
        return max_profile_requests / total_requests > 0.95  # 95% same profile is suspicious

    def _check_endpoint_flooding(self, endpoint: str) -> bool:
        """Check if a single endpoint is being flooded"""
        requests = self.endpoint_requests[endpoint]
        if len(requests) < 100:  # Minimum threshold for consideration
            return False
            
        # Check for unusually regular patterns
        if len(requests) >= 3:
            intervals = np.diff(requests)
            std_dev = np.std(intervals)
            return std_dev < 0.1  # Very regular intervals are suspicious

        return False

    def _check_unusual_timing(self, current_time: float) -> bool:
        """Check if requests are occurring at unusual hours"""
        current_hour = datetime.fromtimestamp(current_time).hour
        return current_hour in self.UNUSUAL_HOURS

    def _check_error_rate(self, ip: str) -> bool:
        """Check if requests are generating too many errors"""
        if not self.status_codes[ip]:
            return False
            
        total_requests = sum(self.status_codes[ip].values())
        error_requests = sum(self.status_codes[ip][code] for code in self.SUSPICIOUS_STATUS_CODES)
        
        return total_requests > 50 and (error_requests / total_requests) > 0.3

    def record_metrics(self, metric_name, value, tags=None):
        point = Point("ddos_metrics")\
            .field(metric_name, value)
            
        if tags:
            for key, value in tags.items():
                point = point.tag(key, value)
                
        self.write_api.write(bucket="ddos_metrics", record=point)

class DDoSMitigator:
    def __init__(self):
        self.blocked_ips: Dict[str, float] = {}
        self.BLOCK_DURATION = 3600  # 1 hour in seconds
        self.logger = logging.getLogger("DDoSMitigator")

    def handle_attack(self, ip: str, attack_type: str) -> dict:
        """
        Implements mitigation strategies for detected attacks.
        Returns mitigation actions taken.
        """
        current_time = time.time()
        
        # Clean expired blocks
        self._clean_expired_blocks(current_time)
        
        mitigation_actions = {
            "ip_blocked": False,
            "rate_limited": False,
            "scale_up": False
        }

        # Block IP if not already blocked
        if ip not in self.blocked_ips:
            self.blocked_ips[ip] = current_time + self.BLOCK_DURATION
            mitigation_actions["ip_blocked"] = True
            self.logger.info(f"Blocking IP {ip} for {self.BLOCK_DURATION} seconds")

        # Trigger auto-scaling if endpoint flooding detected
        if "Endpoint flooding" in attack_type:
            mitigation_actions["scale_up"] = True
            self.logger.info("Triggering auto-scaling due to endpoint flooding")

        # Enable rate limiting for similar IPs
        if "High request rate" in attack_type:
            mitigation_actions["rate_limited"] = True
            self.logger.info(f"Enabling rate limiting for subnet containing {ip}")

        return mitigation_actions

    def _clean_expired_blocks(self, current_time: float) -> None:
        """Remove expired IP blocks"""
        self.blocked_ips = {
            ip: expiry for ip, expiry in self.blocked_ips.items()
            if expiry > current_time
        }
