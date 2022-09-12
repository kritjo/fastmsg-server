use std::str;
use redis::{AsyncCommands};
use serde::{Serialize, Deserialize};
use rand;
use openssl::sign::Verifier;
use openssl::rsa::{Rsa};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use std::fs;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();

    loop{
        let (stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            process_socket(stream).await;
        });
    }
}

async fn process_socket(stream: TcpStream) {
    println!("New connection: {}", stream.peer_addr().unwrap());
    let mut msg = vec![0; 1024];
    loop {
        stream.readable().await.unwrap();
        match stream.try_read(&mut msg) {
            Ok(0) => {
                return;
            }
            Ok(n) => {
                msg.truncate(n);
                break;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(_) => {
                return;
            }
        }
    }
    let str = match str::from_utf8(&msg) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };
    if str.starts_with("AGENT HELLO ") {
        let username = str.trim_start_matches("AGENT HELLO ").trim(); // TODO remove trim
        handle_agent(stream, username).await;
    }
}

#[derive(Serialize, Deserialize)]
struct User {
    pubkey: String,
    keytype: String,
    waiting_messages: Vec<String>,
}

async fn handle_agent(stream: TcpStream, username: &str) {
    let mut connection = get_redis_connection().await;
    let res: String = match connection.get(username).await {
        Ok(v) => v,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };
    let user: User = serde_json::from_str(&res).expect("Unable to parse key");
    // Generate random challenge
    let mut challenge = [0; 32];
    for i in 0..32 {
        challenge[i] = rand::random();
    }
    // Send challenge
    loop {
        stream.writable().await.unwrap();
        match stream.try_write(&challenge) {
            Ok(0) => {
                return;
            }
            Ok(n) => {
                if n == 32 {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(_) => {
                return;
            }
        }
    }
    // Receive signed challenge
    let mut signed_challenge = vec![0; 256];
    loop {
        stream.readable().await.unwrap();
        match stream.try_read(&mut signed_challenge) {
            Ok(0) => {
                return;
            }
            Ok(n) => {
                signed_challenge.truncate(n);
                break;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(_) => {
                return;
            }
        }
    }
    // Verify signed challenge
    let verified = verify_challenge(&challenge, &signed_challenge, &user.pubkey, &user.keytype);
    if verified {
        loop {
            stream.writable().await.unwrap();
            match stream.try_write(b"OK") {
                Ok(0) => {
                    return;
                }
                Ok(n) => {
                    if n == 2 {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(_) => {
                    return;
                }
            }
        }
    } else {
        println!("Not verified: {}", username);
        return;
    }
    loop {
        // Receive message
        let mut msg = vec![0; 1024];
        stream.readable().await.unwrap();
        match stream.try_read(&mut msg) {
            Ok(0) => {
                return;
            }
            Ok(n) => {
                msg.truncate(n);
                if msg == b"POLL" {
                    handle_poll(&stream, username).await;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(_) => {
                return;
            }
        }
    }
}

async fn handle_poll(stream: &TcpStream, username: &str) {
    let mut connection = get_redis_connection().await;
    let mut res: String = match connection.get(username).await {
        Ok(v) => v,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };
    // Create a new user with empty waiting_messages
    let mut user: User = serde_json::from_str(&res).expect("Unable to parse key");
    user.waiting_messages = Vec::new();
    // Use getset to update the user atomically, and get the old value
    res = match connection.getset(username, serde_json::to_string(&user).unwrap()).await {
        Ok(v) => v,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };
    let user_old: User = serde_json::from_str(&res).expect("Unable to parse key");
    if user_old.waiting_messages.len() == 0 {
        loop {
            stream.writable().await.unwrap();
            let mut buf = [0; 1];
            buf[0] = 0;
            match stream.try_write(buf.as_ref()) {
                Ok(0) => {
                    return;
                }
                Ok(n) => {
                    if n == 1 {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(_) => {
                    return;
                }
            }
        }
    } else {
        loop {
            stream.writable().await.unwrap();
            let mut buf = [0; 1];
            buf[0] = 1;
            match stream.try_write(buf.as_ref()) {
                Ok(0) => {
                    return;
                }
                Ok(n) => {
                    if n == buf.len() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(_) => {
                    return;
                }
            }
        }
        loop {
            stream.writable().await.unwrap();
            let mut buf = [0; 4];
            buf[0] = (user_old.waiting_messages.len() >> 24) as u8;
            buf[1] = (user_old.waiting_messages.len() >> 16) as u8;
            buf[2] = (user_old.waiting_messages.len() >> 8) as u8;
            buf[3] = user_old.waiting_messages.len() as u8;
            match stream.try_write(buf.as_ref()) {
                Ok(0) => {
                    return;
                }
                Ok(n) => {
                    if n == 4 {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(_) => {
                    return;
                }
            }
        }
        for msg in user_old.waiting_messages {
            loop {
                let mut buf = [0; 4];
                buf[0] = (msg.len() >> 24) as u8;
                buf[1] = (msg.len() >> 16) as u8;
                buf[2] = (msg.len() >> 8) as u8;
                buf[3] = msg.len() as u8;
                stream.writable().await.unwrap();
                match stream.try_write(buf.as_ref()) {
                    Ok(0) => {
                        return;
                    }
                    Ok(n) => {
                        if n == 4 {
                            break;
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(_) => {
                        return;
                    }
                }
            }
            loop {
                stream.writable().await.unwrap();
                match stream.try_write(msg.as_bytes()) {
                    Ok(0) => {
                        return;
                    }
                    Ok(n) => {
                        if n == msg.len() {
                            break;
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(_) => {
                        return;
                    }
                }
            }
        }
    }
}

async fn get_redis_connection() -> redis::aio::Connection {
    let conf = fs::read_to_string(".conf")
        .expect("Unable to read .conf");
    let mut server_url = String::new();
    for line in conf.lines() {
        if line.starts_with("REDIS_URL") {
            server_url = line.split("=").nth(1).unwrap().to_string().trim().to_string();
        }
    }
    let client: redis::Client = redis::Client::open(server_url).unwrap();
    client.get_async_connection().await.unwrap()
}

fn verify_challenge(challenge: &[u8; 32], signature: &Vec<u8>, pubkey: &String, keytype: &str) -> bool {
    match keytype {
        "RSA" => {
            let rsa = Rsa::public_key_from_pem(pubkey.as_bytes()).unwrap();
            let pkey = PKey::from_rsa(rsa).unwrap();
            let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
            verifier.update(&challenge.as_slice()).unwrap();
            let signature = verifier.verify(&signature).unwrap();
            signature
        },
        _ => panic!("Unsupported key type"),
    }
}