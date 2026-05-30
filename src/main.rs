fn main() {
    println!("\n=======================================================");
    println!("🚀 GREETINGS FROM THE SECURE ENCLAVE!");
    println!("   If you see this, the signature verification PASSED.");
    println!("=======================================================\n");

    if let Ok(hash) = std::env::var("LOADER_PAYLOAD_HASH") {
        println!("My own SHA-256 hash is: {}", hash);
    }

    // Keep PID 2 alive so the loader doesn't reap it
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

