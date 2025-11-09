use clap::Parser;

use rand::Rng;
use rand::seq::SliceRandom;
use serde_json::json;
use std::fs::File;
use std::io::{BufWriter, Write};
use chrono::{DateTime, Utc, Duration};

/// Configuration for log generation
pub struct LogGeneratorConfig {
    pub num_events: usize,
    pub malicious_percentage: f32,
    pub output_path: String,
    pub start_time: DateTime<Utc>,
    pub time_span_hours: i64,
}

impl Default for LogGeneratorConfig {
    fn default() -> Self {
        LogGeneratorConfig {
            num_events: 10000,
            malicious_percentage: 0.2,
            output_path: "generated_logs.json".to_string(),
            start_time: Utc::now() - Duration::hours(24),
            time_span_hours: 24,
        }
    }
}

/// Main log generator
pub struct LogGenerator {
    config: LogGeneratorConfig,
    rng: rand::rngs::ThreadRng,
}

impl LogGenerator {
    pub fn new(config: LogGeneratorConfig) -> Self {
        LogGenerator {
            config,
            rng: rand::thread_rng(),
        }
    }

    /// Generate logs and write to file
    pub fn generate(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let file = File::create(&self.config.output_path)?;
        let mut writer = BufWriter::new(file);

        let num_malicious = (self.config.num_events as f32 * self.config.malicious_percentage) as usize;
        let num_legitimate = self.config.num_events - num_malicious;

        println!("Generating {} events:", self.config.num_events);
        println!("  Legitimate: {}", num_legitimate);
        println!("  Malicious: {}", num_malicious);
        println!("  Output: {}", self.config.output_path);

        let mut events = Vec::new();

        // Generate legitimate events
        for _ in 0..num_legitimate {
            events.push(self.generate_legitimate_event());
        }

        // Generate malicious events
        for _ in 0..num_malicious {
            events.push(self.generate_malicious_event());
        }

        // Shuffle events to mix legitimate and malicious
        events.shuffle(&mut self.rng);

        // Write events to file
        for (i, event) in events.iter().enumerate() {
            writeln!(writer, "{}", serde_json::to_string(&event)?)?;
            
            if (i + 1) % 10000 == 0 {
                println!("  Generated {} events...", i + 1);
            }
        }

        writer.flush()?;
        println!("✓ Successfully generated {} events to {}", self.config.num_events, self.config.output_path);

        Ok(())
    }

    /// Generate a random timestamp within the configured time span
    fn random_timestamp(&mut self) -> String {
        let seconds_offset = self.rng.gen_range(0..self.config.time_span_hours * 3600);
        let timestamp = self.config.start_time + Duration::seconds(seconds_offset);
        timestamp.to_rfc3339()
    }

    /// Generate a random IP address
    fn random_ip(&mut self) -> String {
        format!("{}.{}.{}.{}", 
            self.rng.gen_range(1..255),
            self.rng.gen_range(0..255),
            self.rng.gen_range(0..255),
            self.rng.gen_range(1..255)
        )
    }

    /// Generate a random internal IP address
    fn random_internal_ip(&mut self) -> String {
        let subnet = *["192.168", "10.0", "172.16"].choose(&mut self.rng).unwrap();
        format!("{}.{}.{}", subnet, self.rng.gen_range(0..255), self.rng.gen_range(1..255))
    }

    /// Generate a random username
    fn random_username(&mut self) -> String {
        let usernames = [
            "alice.johnson", "bob.smith", "carol.davis", "david.martinez",
            "emma.wilson", "frank.brown", "grace.lee", "henry.taylor",
            "irene.anderson", "jack.thomas", "karen.white", "leo.jackson",
        ];
        usernames.choose(&mut self.rng).unwrap().to_string()
    }

    /// Generate a legitimate event
    fn generate_legitimate_event(&mut self) -> serde_json::Value {
        let event_types = [
            "authentication", "process_creation", "network_connection", 
            "file_access", "file_creation"
        ];
        
        let event_type = event_types.choose(&mut self.rng).unwrap();
        
        match *event_type {
            "authentication" => self.generate_legitimate_authentication(),
            "process_creation" => self.generate_legitimate_process(),
            "network_connection" => self.generate_legitimate_network(),
            "file_access" => self.generate_legitimate_file_access(),
            "file_creation" => self.generate_legitimate_file_creation(),
            _ => unreachable!(),
        }
    }

    fn generate_legitimate_authentication(&mut self) -> serde_json::Value {
        let protocols = ["ldap", "kerberos", "ntlm"];
        let protocol = protocols.choose(&mut self.rng).unwrap();
        
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "authentication",
            "user": self.random_username(),
            "source_ip": self.random_internal_ip(),
            "destination_ip": format!("10.0.0.{}", self.rng.gen_range(1..50)),
            "status": "success",
            "protocol": protocol,
        })
    }

    fn generate_legitimate_process(&mut self) -> serde_json::Value {
        let processes = [
            ("explorer.exe", "C:\\Windows\\explorer.exe"),
            ("outlook.exe", "C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE"),
            ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
            ("excel.exe", "C:\\Program Files\\Microsoft Office\\Office16\\EXCEL.EXE"),
            ("teams.exe", "C:\\Users\\{}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"),
            ("notepad.exe", "C:\\Windows\\System32\\notepad.exe"),
        ];
        
        let (proc_name, cmd_template) = processes.choose(&mut self.rng).unwrap();
        
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "process_creation",
            "process_name": proc_name,
            "command_line": cmd_template,
            "user": self.random_username(),
            "parent_process": "explorer.exe",
            "pid": self.rng.gen_range(1000..30000),
        })
    }

    fn generate_legitimate_network(&mut self) -> serde_json::Value {
        let domains = [
            ("microsoft.com", "52.96.217.162"),
            ("google.com", "142.250.185.46"),
            ("github.com", "140.82.121.4"),
            ("office365.com", "52.96.217.163"),
            ("zoom.us", "170.114.52.2"),
        ];
        
        let (domain, ip) = domains.choose(&mut self.rng).unwrap();
        
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "network_connection",
            "destination_domain": domain,
            "destination_ip": ip,
            "source_ip": self.random_internal_ip(),
            "port": 443,
            "protocol": "https",
            "bytes_transferred": self.rng.gen_range(10240..1048576),
        })
    }

    fn generate_legitimate_file_access(&mut self) -> serde_json::Value {
        let files = [
            "C:\\Users\\{}\\Documents\\report.docx",
            "C:\\Users\\{}\\Documents\\budget.xlsx",
            "C:\\Users\\{}\\Desktop\\notes.txt",
            "\\\\file-server\\shared\\documents\\project.pdf",
        ];
        
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "file_access",
            "file_path": files.choose(&mut self.rng).unwrap(),
            "user": self.random_username(),
            "action": "read",
            "size": self.rng.gen_range(1024..10485760),
        })
    }

    fn generate_legitimate_file_creation(&mut self) -> serde_json::Value {
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "file_creation",
            "file_path": format!("C:\\Users\\{}\\Documents\\file_{}.docx", 
                self.random_username(), self.rng.gen_range(1000..9999)),
            "user": self.random_username(),
            "size": self.rng.gen_range(10240..1048576),
            "action": "create",
        })
    }

    /// Generate a malicious event
    fn generate_malicious_event(&mut self) -> serde_json::Value {
        let attack_types = [
            "powershell_encoded", "mimikatz", "suspicious_network", 
            "lateral_movement", "credential_dumping", "persistence",
            "privilege_escalation", "reconnaissance", "data_exfiltration"
        ];
        
        let attack_type = attack_types.choose(&mut self.rng).unwrap();
        
        match *attack_type {
            "powershell_encoded" => self.generate_powershell_attack(),
            "mimikatz" => self.generate_mimikatz_attack(),
            "suspicious_network" => self.generate_suspicious_network(),
            "lateral_movement" => self.generate_lateral_movement(),
            "credential_dumping" => self.generate_credential_dumping(),
            "persistence" => self.generate_persistence(),
            "privilege_escalation" => self.generate_privilege_escalation(),
            "reconnaissance" => self.generate_reconnaissance(),
            "data_exfiltration" => self.generate_data_exfiltration(),
            _ => unreachable!(),
        }
    }

    fn generate_powershell_attack(&mut self) -> serde_json::Value {
        let encoded_commands = [
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            "ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA=",
            "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8A",
        ];
        let encoded_cmd = encoded_commands.choose(&mut self.rng).unwrap();
        
        let parent_processes = ["cmd.exe", "winword.exe", "excel.exe"];
        let parent = parent_processes.choose(&mut self.rng).unwrap();
        
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": format!("powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {}", encoded_cmd),
            "user": self.random_username(),
            "parent_process": parent,
            "pid": self.rng.gen_range(1000..30000),
            "suspicious": true,
        })
    }

    fn generate_mimikatz_attack(&mut self) -> serde_json::Value {
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "process_creation",
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
            "user": self.random_username(),
            "parent_process": "powershell.exe",
            "pid": self.rng.gen_range(1000..30000),
            "activity": "credential_dumping",
        })
    }

    fn generate_suspicious_network(&mut self) -> serde_json::Value {
        let malicious_domains = [
            "malicious-site.com", "evil-domain.net", "attacker-c2.ru",
            "bad-server.xyz", "phishing-site.com", "command-control.io"
        ];
        let domain = malicious_domains.choose(&mut self.rng).unwrap();
        
        let ports = [8080, 8443, 4444, 1337];
        let port = ports.choose(&mut self.rng).unwrap();
        
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "network_connection",
            "destination_domain": domain,
            "destination_ip": self.random_ip(),
            "source_ip": self.random_internal_ip(),
            "port": port,
            "protocol": "https",
            "bytes_transferred": self.rng.gen_range(1024..10485760),
            "connection_type": "c2_callback",
        })
    }

    fn generate_lateral_movement(&mut self) -> serde_json::Value {
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "process_creation",
            "process_name": "psexec.exe",
            "command_line": format!("psexec.exe \\\\{} -u admin -p password cmd.exe", 
                self.random_internal_ip()),
            "user": self.random_username(),
            "parent_process": "cmd.exe",
            "pid": self.rng.gen_range(1000..30000),
            "activity": "lateral_movement",
        })
    }

    fn generate_credential_dumping(&mut self) -> serde_json::Value {
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "file_access",
            "file_path": "C:\\Windows\\System32\\config\\SAM",
            "user": "SYSTEM",
            "action": "read",
            "status": "success",
            "suspicious": true,
        })
    }

    fn generate_persistence(&mut self) -> serde_json::Value {
        let registry_keys = ["WindowsUpdate", "SystemUpdate", "SecurityUpdate"];
        let key = registry_keys.choose(&mut self.rng).unwrap();
        
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "registry_modification",
            "registry_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "registry_key": key,
            "registry_value": "C:\\Windows\\Temp\\malware.exe",
            "user": self.random_username(),
            "action": "add",
            "suspicious": true,
        })
    }

    fn generate_privilege_escalation(&mut self) -> serde_json::Value {
        let users = ["administrator", "root", "SYSTEM"];
        let user = users.choose(&mut self.rng).unwrap();
        
        let techniques = ["exploit", "token_manipulation", "bypass_uac"];
        let technique = techniques.choose(&mut self.rng).unwrap();
        
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "authentication",
            "user": user,
            "action": "privilege_escalation",
            "status": "success",
            "technique": technique,
        })
    }

    fn generate_reconnaissance(&mut self) -> serde_json::Value {
        let recon_commands = [
            "whoami /priv", "net user", "net localgroup administrators",
            "ipconfig /all", "systeminfo", "net view"
        ];
        let cmd = recon_commands.choose(&mut self.rng).unwrap();
        
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "command_line": format!("cmd.exe /c {}", cmd),
            "user": self.random_username(),
            "parent_process": "powershell.exe",
            "pid": self.rng.gen_range(1000..30000),
            "activity": "reconnaissance",
        })
    }

    fn generate_data_exfiltration(&mut self) -> serde_json::Value {
        let exfil_sites = [
            "pastebin.com", "dropbox.com", "mega.nz", "file.io"
        ];
        let site = exfil_sites.choose(&mut self.rng).unwrap();
        
        json!({
            "timestamp": self.random_timestamp(),
            "event_type": "network_connection",
            "destination_domain": site,
            "destination_ip": self.random_ip(),
            "source_ip": self.random_internal_ip(),
            "port": 443,
            "protocol": "https",
            "bytes_transferred": self.rng.gen_range(10485760..104857600),
            "direction": "upload",
            "suspicious": true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_log_generator_creation() {
        let config = LogGeneratorConfig::default();
        let generator = LogGenerator::new(config);
        assert!(generator.config.num_events > 0);
    }

    #[test]
    fn test_random_ip_format_2() {
        let mut generator = LogGenerator::new(LogGeneratorConfig::default());
        let ip = generator.random_ip();
        let parts: Vec<&str> = ip.split('.').collect();
        assert_eq!(parts.len(), 4);
    }

    #[test]
    fn test_generate_events() {
        let mut config = LogGeneratorConfig::default();
        config.num_events = 10;
        config.output_path = "/tmp/test_logs.json".to_string();
        
        let mut generator = LogGenerator::new(config);
        let result = generator.generate();
        assert!(result.is_ok());
        
        // Clean up
        let _ = std::fs::remove_file("/tmp/test_logs.json");
    }

    #[test]
    fn test_default_config() {
        let config = LogGeneratorConfig::default();
        assert_eq!(config.num_events, 10000);
        assert_eq!(config.malicious_percentage, 0.2);
        assert!(config.time_span_hours > 0);
    }

    #[test]
    fn test_generator_creation() {
        let config = LogGeneratorConfig::default();
        let generator = LogGenerator::new(config);
        assert_eq!(generator.config.num_events, 10000);
    }

    #[test]
    fn test_random_ip_format() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        let ip = generator.random_ip();
        let parts: Vec<&str> = ip.split('.').collect();
        assert_eq!(parts.len(), 4);
        
        for part in parts {
            let num: Result<u8, _> = part.parse();
            assert!(num.is_ok());
        }
    }

    #[test]
    fn test_random_internal_ip() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        let ip = generator.random_internal_ip();
        assert!(
            ip.starts_with("192.168") || 
            ip.starts_with("10.0") || 
            ip.starts_with("172.16")
        );
    }

    #[test]
    fn test_random_username() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        let username = generator.random_username();
        assert!(!username.is_empty());
        assert!(username.contains('.') || username.len() > 3);
    }

    #[test]
    fn test_random_timestamp() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        let timestamp = generator.random_timestamp();
        assert!(timestamp.contains('T'));
    }

    #[test]
    fn test_generate_legitimate_authentication() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        let event = generator.generate_legitimate_authentication();
        assert_eq!(event["event_type"], "authentication");
        assert!(event["user"].is_string());
        assert!(event["status"].is_string());
    }

    #[test]
    fn test_generate_legitimate_process() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        let event = generator.generate_legitimate_process();
        assert_eq!(event["event_type"], "process_creation");
        assert!(event["process_name"].is_string());
        assert!(event["command_line"].is_string());
        assert!(event["pid"].is_number());
    }

    #[test]
    fn test_generate_legitimate_network() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        let event = generator.generate_legitimate_network();
        assert_eq!(event["event_type"], "network_connection");
        assert!(event["destination_domain"].is_string());
        assert!(event["port"].is_number());
    }

    #[test]
    fn test_generate_powershell_attack() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        let event = generator.generate_powershell_attack();
        assert_eq!(event["event_type"], "process_creation");
        assert_eq!(event["process_name"], "powershell.exe");
        assert!(event["command_line"].as_str().unwrap().contains("EncodedCommand"));
        assert_eq!(event["suspicious"], true);
    }

    #[test]
    fn test_generate_mimikatz_attack() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        let event = generator.generate_mimikatz_attack();
        assert_eq!(event["process_name"], "mimikatz.exe");
        assert_eq!(event["activity"], "credential_dumping");
    }

    #[test]
    fn test_generate_suspicious_network() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        let event = generator.generate_suspicious_network();
        assert_eq!(event["event_type"], "network_connection");
        assert_eq!(event["connection_type"], "c2_callback");
    }

    #[test]
    fn test_generate_small_log_file() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("test_logs.json");
        
        let config = LogGeneratorConfig {
            num_events: 100,
            malicious_percentage: 0.2,
            output_path: output_path.to_str().unwrap().to_string(),
            start_time: chrono::Utc::now() - chrono::Duration::hours(1),
            time_span_hours: 1,
        };
        
        let mut generator = LogGenerator::new(config);
        let result = generator.generate();
        
        assert!(result.is_ok());
        assert!(output_path.exists());
        
        // Check file content
        let content = fs::read_to_string(&output_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 100);
        
        // Verify each line is valid JSON
        for line in lines {
            let json: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(json.is_ok());
        }
    }

    #[test]
    fn test_malicious_percentage() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("test_malicious.json");
        
        let config = LogGeneratorConfig {
            num_events: 1000,
            malicious_percentage: 0.3,
            output_path: output_path.to_str().unwrap().to_string(),
            start_time: chrono::Utc::now() - chrono::Duration::hours(1),
            time_span_hours: 1,
        };
        
        let mut generator = LogGenerator::new(config);
        generator.generate().unwrap();
        
        // Read and count suspicious events
        let content = fs::read_to_string(&output_path).unwrap();
        let mut suspicious_count = 0;
        
        for line in content.lines() {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            if event.get("suspicious") == Some(&serde_json::Value::Bool(true)) ||
               event.get("activity").is_some() {
                suspicious_count += 1;
            }
        }
        
        // Should be approximately 30% (allow some variance due to randomness)
        let expected = 300;
        let tolerance = 100; // Allow ±100 events
        assert!(suspicious_count > expected - tolerance && suspicious_count < expected + tolerance);
    }

    #[test]
    fn test_event_types_variety() {
        let config = LogGeneratorConfig {
            num_events: 100,
            malicious_percentage: 0.5,
            output_path: "/tmp/test_variety.json".to_string(),
            start_time: chrono::Utc::now(),
            time_span_hours: 1,
        };
        
        let mut generator = LogGenerator::new(config);
        
        // Generate some legitimate events
        let mut event_types = std::collections::HashSet::new();
        for _ in 0..20 {
            let event = generator.generate_legitimate_event();
            event_types.insert(event["event_type"].as_str().unwrap().to_string());
        }
        
        // Should have variety
        assert!(event_types.len() >= 3);
        
        // Clean up
        let _ = fs::remove_file("/tmp/test_variety.json");
    }

    #[test]
    fn test_timestamp_ordering() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("test_timestamps.json");
        
        let start = chrono::Utc::now() - chrono::Duration::hours(24);
        
        let config = LogGeneratorConfig {
            num_events: 100,
            malicious_percentage: 0.2,
            output_path: output_path.to_str().unwrap().to_string(),
            start_time: start,
            time_span_hours: 24,
        };
        
        let mut generator = LogGenerator::new(config);
        generator.generate().unwrap();
        
        let content = fs::read_to_string(&output_path).unwrap();
        for line in content.lines() {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            let timestamp = event["timestamp"].as_str().unwrap();
            
            // Parse timestamp
            let parsed = chrono::DateTime::parse_from_rfc3339(timestamp);
            assert!(parsed.is_ok());
            
            // Should be within the time span
            let event_time = parsed.unwrap().with_timezone(&chrono::Utc);
            let end = start + chrono::Duration::hours(24);
            assert!(event_time >= start && event_time <= end);
        }
    }

    #[test]
    fn test_all_required_fields() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        // Test legitimate events have required fields
        let legit = generator.generate_legitimate_event();
        assert!(legit.get("timestamp").is_some());
        assert!(legit.get("event_type").is_some());
        
        // Test malicious events have required fields
        let mal = generator.generate_malicious_event();
        assert!(mal.get("timestamp").is_some());
        assert!(mal.get("event_type").is_some());
    }

    #[test]
    fn test_ip_validity() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        for _ in 0..10 {
            let ip = generator.random_ip();
            let parts: Vec<&str> = ip.split('.').collect();
            assert_eq!(parts.len(), 4);
            
            for part in parts {
                let num: u8 = part.parse().unwrap();
                assert!(num < 255);
            }
        }
    }

    #[test]
    fn test_json_validity() {
        let config = LogGeneratorConfig::default();
        let mut generator = LogGenerator::new(config);
        
        // Test that all generated events are valid JSON
        for _ in 0..10 {
            let event = generator.generate_legitimate_event();
            let json_str = serde_json::to_string(&event).unwrap();
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
            assert!(parsed.is_ok());
        }
        
        for _ in 0..10 {
            let event = generator.generate_malicious_event();
            let json_str = serde_json::to_string(&event).unwrap();
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
            assert!(parsed.is_ok());
        }
    }
}


#[derive(Parser, Debug)]
#[command(author, version, about = "Generate random security log files for testing", long_about = None)]
struct Args {
    /// Number of events to generate
    #[arg(short, long, default_value = "10000")]
    num_events: usize,

    /// Percentage of malicious events (0.0 to 1.0)
    #[arg(short = 'm', long, default_value = "0.2")]
    malicious_percentage: f32,

    /// Output file path
    #[arg(short, long, default_value = "generated_logs.json")]
    output: String,

    /// Time span in hours for event timestamps
    #[arg(short = 't', long, default_value = "24")]
    time_span_hours: i64,

    /// Seed for random number generator (for reproducibility)
    #[arg(short, long)]
    seed: Option<u64>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Validate malicious percentage
    if args.malicious_percentage < 0.0 || args.malicious_percentage > 1.0 {
        eprintln!("Error: Malicious percentage must be between 0.0 and 1.0");
        std::process::exit(1);
    }

    println!("╔══════════════════════════════════════════╗");
    println!("║   Sigma Log Generator                    ║");
    println!("╚══════════════════════════════════════════╝");
    println!();

    if let Some(seed) = args.seed {
        println!("Using seed: {}", seed);
        println!();
    }

    let config = LogGeneratorConfig {
        num_events: args.num_events,
        malicious_percentage: args.malicious_percentage,
        output_path: args.output.clone(),
        start_time: Utc::now() - chrono::Duration::hours(args.time_span_hours),
        time_span_hours: args.time_span_hours,
    };

    let mut generator = LogGenerator::new(config);
    
    let start = std::time::Instant::now();
    generator.generate()?;
    let duration = start.elapsed();

    println!();
    println!("═══════════════════════════════════════════");
    println!("Generation Statistics:");
    println!("  Total events: {}", args.num_events);
    println!("  Malicious: {} ({:.1}%)", 
        (args.num_events as f32 * args.malicious_percentage) as usize,
        args.malicious_percentage * 100.0);
    println!("  Legitimate: {} ({:.1}%)", 
        (args.num_events as f32 * (1.0 - args.malicious_percentage)) as usize,
        (1.0 - args.malicious_percentage) * 100.0);
    println!("  Time span: {} hours", args.time_span_hours);
    println!("  Generation time: {:.2}s", duration.as_secs_f64());
    println!("  Output file: {}", args.output);
    println!("═══════════════════════════════════════════");
    println!();
    println!("Usage example:");
    println!("  sigma-evaluator -r examples/rules -l {}", args.output);
    println!();

    Ok(())
}
