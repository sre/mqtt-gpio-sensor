// © 2020 Sebastian Reichel
// SPDX-License-Identifier: ISC

extern crate rumqtt;
extern crate mqtt311;
extern crate gpiochip as gpio;
extern crate ini;
extern crate libc;
extern crate seccomp_sys as sc;

use std::io::{Error,ErrorKind};
use rumqtt::{MqttClient, MqttOptions, SecurityOptions, QoS, Receiver, Notification};

fn set_uid(username : &str) -> std::io::Result<()> {
    let p : &libc::passwd = unsafe {
        let cstr = std::ffi::CString::new(username).expect("Unable to pass username to underlying C library");
        let p = libc::getpwnam(cstr.as_ptr());
        if p.is_null() {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }
        &*p
    };

    match unsafe { libc::setgid(p.pw_gid) } {
        0 => {},
        -1 => {
            return Err(Error::last_os_error())
        },
        n => unreachable!("setgid returned {}", n)
    }

    match unsafe { libc::setuid(p.pw_uid) } {
        0 => {},
        -1 => {
            return Err(Error::last_os_error())
        },
        n => unreachable!("setuid returned {}", n)
    }

    Ok(())
}

pub fn drop_root(cfg: &ini::Ini) -> std::io::Result<()> {
    let username = match cfg.get_from(Some("CORE"), "username") {
        Some(x) => x,
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify process username"));
        }
    };

    set_uid(username)?;
    println!("Dropped root permissions");
    Ok(())
}

pub fn seccomp_allow_syscall(ctx: *mut libc::c_void, syscall: libc::c_long) -> std::io::Result<()> {
    let ret: libc::c_int;

    unsafe {
        ret = sc::seccomp_rule_add(ctx, sc::SCMP_ACT_ALLOW, syscall as libc::c_int, 0);
    }

    if ret != 0 {
        eprintln!("seccomp_rule_add {} -> {}", syscall, ret);
        return Err(Error::new(ErrorKind::Other, "Failed to add seccomp rule"));
    }

    Ok(())
}

pub fn enable_seccomp() -> std::io::Result<()> {
    let ctx: *mut libc::c_void;
    let ret: libc::c_int;

    unsafe {
        ctx = sc::seccomp_init(sc::SCMP_ACT_ERRNO(libc::EPERM as u32));
    }

    if ctx == std::ptr::null_mut() {
        return Err(Error::new(ErrorKind::Other, "Failed to init seccomp"));
    }

    seccomp_allow_syscall(ctx, libc::SYS_exit)?;
    seccomp_allow_syscall(ctx, libc::SYS_exit_group)?;
    seccomp_allow_syscall(ctx, libc::SYS_uname)?;

    seccomp_allow_syscall(ctx, libc::SYS_clone)?;
    seccomp_allow_syscall(ctx, libc::SYS_sched_yield)?;
    seccomp_allow_syscall(ctx, libc::SYS_sched_getaffinity)?;
    seccomp_allow_syscall(ctx, libc::SYS_pipe2)?;
    seccomp_allow_syscall(ctx, libc::SYS_futex)?;
    seccomp_allow_syscall(ctx, libc::SYS_set_robust_list)?;
    seccomp_allow_syscall(ctx, libc::SYS_sigaltstack)?;
    seccomp_allow_syscall(ctx, libc::SYS_nanosleep)?;

    seccomp_allow_syscall(ctx, libc::SYS_openat)?;
    seccomp_allow_syscall(ctx, libc::SYS_close)?;
    seccomp_allow_syscall(ctx, libc::SYS_ioctl)?;
    seccomp_allow_syscall(ctx, libc::SYS_read)?;
    seccomp_allow_syscall(ctx, libc::SYS_write)?;
    seccomp_allow_syscall(ctx, libc::SYS_statx)?;
    #[cfg(all(unix, target_pointer_width = "32"))]
    seccomp_allow_syscall(ctx, libc::SYS_stat64)?;
    #[cfg(all(unix, target_pointer_width = "64"))]
    seccomp_allow_syscall(ctx, libc::SYS_stat)?;
    #[cfg(all(unix, target_pointer_width = "32"))]
    seccomp_allow_syscall(ctx, libc::SYS_fstat64)?;
    #[cfg(all(unix, target_pointer_width = "64"))]
    seccomp_allow_syscall(ctx, libc::SYS_fstat)?;
    #[cfg(all(unix, target_pointer_width = "32"))]
    seccomp_allow_syscall(ctx, libc::SYS__llseek)?;
    #[cfg(all(unix, target_pointer_width = "64"))]
    seccomp_allow_syscall(ctx, libc::SYS_lseek)?;
    #[cfg(all(unix, target_pointer_width = "32"))]
    seccomp_allow_syscall(ctx, libc::SYS_fcntl64)?;
    #[cfg(all(unix, target_pointer_width = "64"))]
    seccomp_allow_syscall(ctx, libc::SYS_fcntl)?;

    #[cfg(all(unix, target_pointer_width = "32"))]
    seccomp_allow_syscall(ctx, libc::SYS_mmap2)?;
    #[cfg(all(unix, target_pointer_width = "64"))]
    seccomp_allow_syscall(ctx, libc::SYS_mmap)?;
    seccomp_allow_syscall(ctx, libc::SYS_munmap)?;
    seccomp_allow_syscall(ctx, libc::SYS_mprotect)?;

    seccomp_allow_syscall(ctx, libc::SYS_clock_gettime)?;
    seccomp_allow_syscall(ctx, libc::SYS_gettimeofday)?;

    seccomp_allow_syscall(ctx, libc::SYS_epoll_create1)?;
    seccomp_allow_syscall(ctx, libc::SYS_epoll_ctl)?;
    seccomp_allow_syscall(ctx, libc::SYS_epoll_wait)?;
    seccomp_allow_syscall(ctx, libc::SYS_poll)?;

    seccomp_allow_syscall(ctx, libc::SYS_bind)?;
    seccomp_allow_syscall(ctx, libc::SYS_socket)?;
    seccomp_allow_syscall(ctx, libc::SYS_getsockname)?;
    seccomp_allow_syscall(ctx, libc::SYS_connect)?;
    seccomp_allow_syscall(ctx, libc::SYS_getsockopt)?;
    seccomp_allow_syscall(ctx, libc::SYS_getrandom)?;
    #[cfg(target_arch = "arm")]
    seccomp_allow_syscall(ctx, libc::SYS_recv)?;
    #[cfg(target_arch = "arm")]
    seccomp_allow_syscall(ctx, libc::SYS_send)?;
    seccomp_allow_syscall(ctx, libc::SYS_recvmsg)?;
    seccomp_allow_syscall(ctx, libc::SYS_recvfrom)?;
    seccomp_allow_syscall(ctx, libc::SYS_sendto)?;
    seccomp_allow_syscall(ctx, libc::SYS_sendmmsg)?;

    unsafe {
        ret = sc::seccomp_load(ctx);
    }

    if ret != 0 {
        eprintln!("seccomp_load -> {}", ret);
        return Err(Error::new(ErrorKind::Other, "Failed to load seccomp rules"));
    }

    println!("Enabled seccomp protection");
    Ok(())
}

fn get_cfg() -> std::io::Result<ini::Ini> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 1 {
        return Err(Error::new(ErrorKind::Other, "Empty arguments"));
    }

    if args.len() < 2 {
        eprintln!("Usage: {} <config>", args[0]);
        return Err(Error::new(ErrorKind::Other, "Config file not specified"));
    }

    return match ini::Ini::load_from_file(&args[1]) {
        Ok(x) => Ok(x),
        Err(e) => {
            eprintln!("Config error: {}", e);
            return Err(Error::new(ErrorKind::Other, "Failed to load config file"));
        }
    };
}

fn get_mqtt(cfg: &ini::Ini) -> std::io::Result<(MqttClient, Receiver<Notification>)> {
    let server = match cfg.get_from(Some("MQTT"), "server") {
        Some(x) => x,
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify MQTT server"));
        }
    };

    let port = match cfg.get_from(Some("MQTT"), "port") {
        Some(x) => match x.parse() {
            Ok(num) => num,
            Err(e) => {
                eprintln!("Could not parse port number: {}", e);
                return Err(Error::new(ErrorKind::Other, "Could not parse MQTT port number"));
            }
        },
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify MQTT port"));
        }
    };

    let clientname = match cfg.get_from(Some("MQTT"), "client-name") {
        Some(x) => x,
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify MQTT client name"));
        }
    };

    let username = match cfg.get_from(Some("MQTT"), "username") {
        Some(x) => x,
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify MQTT username"));
        }
    };

    let password = match cfg.get_from(Some("MQTT"), "password") {
        Some(x) => x,
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify MQTT password"));
        }
    };

    let topic = match cfg.get_from(Some("MQTT"), "topic") {
        Some(x) => x,
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify MQTT topic"));
        }
    };

    let certificate = match cfg.get_from(Some("MQTT"), "certificate") {
        Some(x) => x,
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify MQTT certificate"));
        }
    };

    let ca = std::fs::read(certificate)?;

    let security_options = SecurityOptions::UsernamePassword(username.to_string(), password.to_string());

    let last_will = mqtt311::LastWill {
        topic: topic.to_string(),
        message: "-1".to_string(),
        qos: QoS::AtLeastOnce,
        retain: true
    };

    let mqtt_options = MqttOptions::new(clientname, server, port)
        .set_keep_alive(10)
        .set_ca(ca)
        .set_security_opts(security_options)
        .set_last_will(last_will);

    return match MqttClient::start(mqtt_options) {
        Ok(x) => Ok(x),
        Err(e) => {
            eprintln!("MQTT error: {}", e);
            return Err(Error::new(ErrorKind::Other, "Failed to start MQTT"))
        }
    };
}

fn get_gpio(cfg: &ini::Ini) -> std::io::Result<gpio::GpioEventHandle> {
    let gpioname = match cfg.get_from(Some("GPIO"), "label") {
        Some(x) => x,
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify GPIO label"));
        }
    };

    let gpiodev = match cfg.get_from(Some("GPIO"), "device") {
        Some(x) => x,
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify GPIO device"));
        }
    };

    let gpionum = match cfg.get_from(Some("GPIO"), "number") {
        Some(x) => match x.parse() {
            Ok(num) => num,
            Err(e) => {
                eprintln!("Could not parse GPIO number: {}", e);
                return Err(Error::new(ErrorKind::Other, "Could not parse GPIO number"));
            }
        },
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify GPIO number"));
        }
    };

    let activelow = match cfg.get_from(Some("GPIO"), "active-low") {
        Some(x) => x.to_lowercase(),
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify GPIO logic type"));
        }
    };

    let mut flags = gpio::RequestFlags::INPUT;

    if activelow == "true" || activelow == "yes" {
        flags = flags | gpio::RequestFlags::ACTIVE_LOW;
    }

    let chip = gpio::GpioChip::new(gpiodev)?;

    let gpio = chip.request_event(gpioname, gpionum, flags, gpio::EventRequestFlags::BOTH_EDGES)?;

    return Ok(gpio);
}

fn publish_mqtt(mut mqtt_client: MqttClient, topic: &str, message: &str) -> std::io::Result<()> {
    println!("{} -> {}", topic, message);

    mqtt_client.publish(topic, QoS::AtLeastOnce, true, message.as_bytes().to_vec()).expect("Could not send");

    Ok(())
}

fn gpio_event_handler(cfg: &ini::Ini, mqtt_client: MqttClient, gpio: &gpio::GpioEventHandle) -> std::io::Result<()> {
    let topic = match cfg.get_from(Some("MQTT"), "topic") {
        Some(x) => x,
        None => {
            return Err(Error::new(ErrorKind::Other, "Config file does not specify MQTT topic"));
        }
    };

    let initial_state = gpio.get()?;
    if initial_state == 0 {
        publish_mqtt(mqtt_client.clone(), topic, "0")?;
    } else {
        publish_mqtt(mqtt_client.clone(), topic, "1")?;
    }

    loop {
        let bitmap = gpio::wait_for_event(&[&gpio], 1000)?;
        if bitmap & 0b1 == 0b1 {
            let event = gpio.read()?;

            if event.id == gpio::EventId::RISING_EDGE {
                publish_mqtt(mqtt_client.clone(), topic, "1")?;
            } else if event.id == gpio::EventId::FALLING_EDGE {
                publish_mqtt(mqtt_client.clone(), topic, "0")?;
            } else {
                return Err(Error::new(ErrorKind::Other, "Unknown GPIO state change"));
            }
        }
    }
}

fn main_err() -> std::io::Result<()> {
    println!("MQTT GPIO Sensor");

    let cfg = get_cfg()?;
    let gpio = get_gpio(&cfg)?;

    drop_root(&cfg)?;
    enable_seccomp()?;

    let (mqtt_client, notifications) = get_mqtt(&cfg)?;

    std::thread::spawn(move || {
        match gpio_event_handler(&cfg, mqtt_client, &gpio) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    });

    for notification in notifications {
        match notification {
            rumqtt::client::Notification::Disconnection => {
                return Err(Error::new(ErrorKind::Other, "Disconnected from MQTT Server!"));
            },
            _ => println!("{:?}", notification),
        }
    }

    Ok(())
}

fn main() {
    match main_err() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
