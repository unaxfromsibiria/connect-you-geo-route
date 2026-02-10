use std::env;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use tokio::io::copy_bidirectional_with_sizes;
use log::{info, warn, error};

// env variables
const ENV_SOCKET_LISTEN: &str = "TCP_SOCKET_LISTEN";  // value eg: 0.0.0.0:7000
const ENV_TARGET_SOCKET: &str = "TCP_SOCKET_TARGET";  // value eg: 10.1.1.10:8080
const ENV_GUEST_SOCKET: &str = "TCP_SOCKET_GUEST";  // value eg: 10.1.1.10:8000
const ENV_WHITE_LIST: &str = "IP_WHITE_LIST"; // value eg: 127.0.0.1;10.1.1.2
const ENV_BUFFER_SIZE: &str = "BUFFER_SIZE";
const ENV_STAT_SHOW_INTERVAL: &str = "STAT_SHOW_INTERVAL";
const ENV_GEOIP_DB: &str = "GEOIP_DB_PATH";
const ENV_CITY_LIST: &str = "CITY_LIST";  // value eg: London;Rome;Beijing

#[derive(Clone)]
struct Settings {
    ip_addresses: Vec<String>,
    cities: Vec<String>,
    listen_socket: Option<(String, u16)>,
    target_socket: Option<(String, u16)>,
    guest_socket: Option<(String, u16)>,
    buffer_size: usize,
    stat_delay: usize,
    file_path_mmdb: String,
}

trait DataValidator {
    fn is_allowed(&self, ip: &str) -> bool;
    fn is_city_allowed(&self, ip: &str, db: &Reader<Vec<u8>>) -> bool;
}

impl DataValidator for Settings {
    fn is_allowed(&self, ip: &str) -> bool {
        self.ip_addresses.contains(&ip.to_string())
    }

    fn is_city_allowed(&self, ip: &str, db: &Reader<Vec<u8>>) -> bool {
        let ip_addr = match ip.parse::<IpAddr>() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        match db.lookup(ip_addr) {
            Ok(lookup_result) => {
                match lookup_result.decode::<geoip2::City>() {
                    Ok(city) => {
                        let city_info = match city {
                            Some(city_data) => city_data,
                            None => {
                                info!("No city for ip {}", ip);
                                return false
                            },
                        };
                        let name = city_info.city.names.english;
                        let name = match name {
                            Some(name_str) => name_str,
                            None => return false,
                        };
                        info!("City: {} with ip {}", name, ip);
                        self.cities.contains(&name.to_string().to_lowercase())
                    },
                    Err(_) => false
                }
            },
            Err(_) => false,
        }
    }
}

fn _validate_port(val: u32) -> bool {
    val > 0 && val <= 65535
}

fn _validate_id(val: &str) -> bool {
    let parts: Vec<&str> = val.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for part in parts {
        match part.parse::<u32>() {
            Ok(num) => {
                if num > 255 {
                    return false;
                }
            }
            Err(_) => {
                return false;
            }
        }
    }
    true
}

fn _validate_socket(val: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = val.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip = parts[0].to_string();
    let port = match parts[1].parse::<u32>() {
        Ok(port) => port,
        Err(_) => return None,
    };
    if !_validate_id(&ip) || !_validate_port(port) {
        return None;
    }
    Some((ip, port as u16))
}

fn _validate_uint_size(val: &str) -> Option<usize> {
    val.parse::<usize>().ok()
}

fn create_settings() -> Settings {
    let ip_list = match env::var(ENV_WHITE_LIST) {
        Ok(val) => val,
        Err(e) => {
            warn!("Error getting {}: {}", ENV_WHITE_LIST, e);
            "".to_string()
        },
    };
    let ip_addresses: Vec<String> = ip_list.split(';').map(
        |s| s.trim().to_string()
    ).filter(|s| !s.is_empty() && _validate_id(s)).collect();
    info!("Allow from: {:?}", ip_addresses);

    let listen_socket = match env::var(ENV_SOCKET_LISTEN) {
        Ok(val) => _validate_socket(&val),
        Err(e) => {
            warn!("Error getting {}: {}", ENV_SOCKET_LISTEN, e);
            None
        },
    };
    if let Some((listen_ip, listen_port)) = &listen_socket {
        info!("Listen on: {}:{}", listen_ip, listen_port);
    }

    let target_socket = match env::var(ENV_TARGET_SOCKET) {
        Ok(val) => _validate_socket(&val),
        Err(e) => {
            warn!("Error getting {}: {}", ENV_TARGET_SOCKET, e);
            None
        },
    };
    if let Some((target_ip, target_port)) = &target_socket {
        info!("Target: {}:{}", target_ip, target_port);
    }

    let guest_socket = match env::var(ENV_GUEST_SOCKET) {
        Ok(val) => _validate_socket(&val),
        Err(e) => {
            warn!("Error getting {}: {}", ENV_GUEST_SOCKET, e);
            None
        },
    };
    if let Some((guest_ip, guest_port)) = &guest_socket {
        info!("Guest: {}:{}", guest_ip, guest_port);
    }

    let buffer_size = match env::var(ENV_BUFFER_SIZE) {
        Ok(val) => _validate_uint_size(&val).unwrap_or(2048),
        Err(_) => 2048,
    };
    info!("Buffer size: {}", buffer_size);

    let stat_delay = match env::var(ENV_STAT_SHOW_INTERVAL) {
        Ok(val) => _validate_uint_size(&val).unwrap_or(60),
        Err(_) => 60,
    };

    let file_path_mmdb = match env::var(ENV_GEOIP_DB) {
        Ok(val) => val,
        Err(_) => {
            warn!("Using default value for {}: data/GeoLite2-City.mmdb", ENV_GEOIP_DB);
            "data/GeoLite2-City.mmdb".to_string()
        },
    };

    let cities_line = match env::var(ENV_CITY_LIST) {
        Ok(val) => val,
        Err(e) => {
            warn!("Error getting {}: {}", ENV_CITY_LIST, e);
            "".to_string()
        },
    };

    let cities = cities_line.split(';').map(
        |s| s.trim().to_string().to_lowercase()
    ).filter(|s| !s.is_empty()).collect();

    Settings {
        cities,
        ip_addresses,
        listen_socket,
        target_socket,
        guest_socket,
        buffer_size,
        stat_delay,
        file_path_mmdb,
    }
}

async fn print_traffic_stats(traffic: Arc<Mutex<HashMap<String, u64>>>, stat_delay: usize) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(stat_delay as u64)).await;
        let traffic_guard = traffic.lock().await;
        let mut ip_stats: HashMap<String, (u64, u64)> = HashMap::new();

        for (key, value) in traffic_guard.iter() {
            if let Some(ip) = key.strip_suffix("_in") {
                ip_stats.entry(ip.to_string()).or_insert((0, 0)).0 += *value;
            } else if let Some(ip) = key.strip_suffix("_out") {
                ip_stats.entry(ip.to_string()).or_insert((0, 0)).1 += *value;
            }
        }

        info!("traffic:");
        for (ip, (in_value, out_value)) in ip_stats {
            let print_value = |value: u64| -> (f64, &'static str) {
                if value >= 1024 * 1024 {
                    let mb = (value as f64 / (1024.0 * 1024.0)) * 10.0;
                    (mb.round() / 10.0, "mb")
                } else {
                    let kb = (value as f64 / 1024.0) * 10.0;
                    (kb.round() / 10.0, "kb")
                }
            };

            let (in_value_formatted, in_unit) = print_value(in_value);
            let (out_value_formatted, out_unit) = print_value(out_value);

            info!(
                "  client {} in: {:.1} {} out: {:.1} {}",
                ip, in_value_formatted, in_unit, out_value_formatted, out_unit
            );
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let traffic: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let ip_cache: Arc<Mutex<HashMap<String, bool>>> = Arc::new(Mutex::new(HashMap::new()));
    let settings = create_settings();
    let reader = Reader::open_readfile(&settings.file_path_mmdb)?;
    let reader_arc = Arc::new(Mutex::new(reader));
    let listener = match settings.listen_socket.clone() {
        Some((ip, port)) => TcpListener::bind(format!("{}:{}", ip, port)).await?,
        None => return Err("Listen socket configuration is missing".into()),
    };
    let traffic_clone = Arc::clone(&traffic);
    tokio::spawn(async move {
        print_traffic_stats(traffic_clone, settings.stat_delay).await;
    });

    while let Ok((mut inbound, addr)) = listener.accept().await {
        let ip_cache_clone = Arc::clone(&ip_cache);
        let local_settings = settings.clone();
        let ip = addr.ip().to_string();
        let is_allow_ip = {
            let ip_cache_guard = ip_cache_clone.lock().await;
            if let Some(&cached_value) = ip_cache_guard.get(&ip) {
                info!("Ip {} from a cache", ip);
                cached_value
            } else {
                let mut allowed = local_settings.is_allowed(&ip);
                if !allowed {
                    let reader_guard = reader_arc.lock().await;
                    allowed = local_settings.is_city_allowed(&ip, &reader_guard);
                }
                drop(ip_cache_guard);
                let mut ip_cache_guard = ip_cache_clone.lock().await;
                ip_cache_guard.insert(ip.clone(), allowed);
                drop(ip_cache_guard);
                allowed
            }
        };
        if is_allow_ip {
            info!("connection from {} allowed", ip);
        } else {
            warn!("connection from {} forbidden", ip);
        }
        let target_socket_config = if is_allow_ip {
            local_settings.target_socket.clone()
        } else {
            local_settings.guest_socket.clone()
        };
        let target_socket_config = match target_socket_config {
            Some((ip, port)) => (ip, port),
            None => {
                error!("Target socket configuration is missing");
                break;
            }
        };
        let server_addr = format!("{}:{}", target_socket_config.0, target_socket_config.1);
        let mut outbound = TcpStream::connect(server_addr).await?;
        let traffic_arc = Arc::clone(&traffic);
        tokio::spawn(async move {
            let b_s = local_settings.buffer_size;
            let result = copy_bidirectional_with_sizes(
                &mut inbound, &mut outbound, b_s, b_s
            ).await;
            match result {
                Ok((to_server, from_server)) => {
                    info!("Bytes sent from {}: {}, received: {}", ip, to_server, from_server);
                    let (traffic_in_key, traffic_out_key) = (format!("{}_in", ip), format!("{}_out", ip));
                    let mut traffic_guard = traffic_arc.lock().await;
                    *traffic_guard.entry(traffic_in_key.clone()).or_insert(0) += to_server;
                    *traffic_guard.entry(traffic_out_key.clone()).or_insert(0) += from_server;
                    drop(traffic_guard);
                }
                Err(e) => {
                    error!("Error during bidirectional copy: {}", e);
                }
            }
        });
    }
    Ok(())
}