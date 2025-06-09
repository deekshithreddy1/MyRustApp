use std::fs;
use std::io::{self, Write};

// --- XOR Cipher Function ---
fn xor_cipher(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        // For decryption, an empty key should ideally result in an error or no change.
        // For encryption, it's a warning and no encryption.
        // Let's keep it consistent: no operation if key is empty.
        println!("Warning: Empty key used. No cipher operation performed.");
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % key.len()])
        .collect()
}

// --- Filename Sanitization Function ---
fn sanitize_filename(name: &str) -> String {
    let forbidden_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|'];
    let mut sanitized: String = name
        .chars()
        .map(|c| if forbidden_chars.contains(&c) || c.is_control() { '_' } else { c })
        .collect();
    while sanitized.contains("__") {
        sanitized = sanitized.replace("__", "_");
    }
    sanitized = sanitized.trim_matches(|c: char| c == '_' || c.is_whitespace()).to_string();
    if sanitized.is_empty() || sanitized.chars().all(|c| c == '_') {
        "unnamed_record".to_string()
    } else {
        let max_len = 50;
        if sanitized.len() > max_len {
            sanitized.truncate(max_len);
            sanitized = sanitized.trim_end_matches('_').to_string();
        }
        sanitized
    }
}

// --- Helper to convert Hex String to Bytes ---
fn hex_string_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    let clean_hex_str = hex_str.trim(); // Remove any leading/trailing whitespace
    if clean_hex_str.len() % 2 != 0 {
        return Err("Hex string must have an even number of characters.".to_string());
    }
    (0..clean_hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean_hex_str[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| format!("Invalid hex character: {}", e))
}

// --- Encryption Logic ---
fn encrypt_and_save_data() {
    print!("Enter Heading: ");
    io::stdout().flush().unwrap();
    let mut heading_input = String::new();
    io::stdin().read_line(&mut heading_input).expect("Failed to read heading line");
    let heading = heading_input.trim();

    print!("Enter Your Data (to be encrypted): ");
    io::stdout().flush().unwrap();
    let mut user_data_input = String::new();
    io::stdin().read_line(&mut user_data_input).expect("Failed to read data line");
    let user_data = user_data_input.trim();

    if user_data.is_empty() {
        println!("No data entered for encryption. Aborting.");
        return;
    }

    print!("Enter Your Secret Key: ");
    io::stdout().flush().unwrap();
    let mut secret_key_input = String::new();
    io::stdin().read_line(&mut secret_key_input).expect("Failed to read secret key line");
    let secret_key = secret_key_input.trim();

    if secret_key.is_empty() {
        println!("Secret key cannot be empty for encryption. Aborting.");
        return;
    }

    let data_bytes = user_data.as_bytes();
    let key_bytes = secret_key.as_bytes();
    let encrypted_bytes = xor_cipher(data_bytes, key_bytes);
    let hex_encrypted_string: String = encrypted_bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();

    println!("\n--- Encrypted Record (Console Output) ---");
    println!("Original Heading: {}", heading); // For console clarity
    println!("Encrypted Data (Hex): {}", hex_encrypted_string);

    // As per your last modification, the file only contains the hex string
    let file_content = hex_encrypted_string;

    let mut filename_base = sanitize_filename(heading);
    if filename_base.is_empty() {
        filename_base = "encrypted_record".to_string();
    }
    let filename = format!("{}.txt", filename_base);

    match fs::write(&filename, file_content) {
        Ok(_) => println!("\nSuccessfully saved encrypted data to file: {}", filename),
        Err(e) => eprintln!("\nError saving file '{}': {}", filename, e),
    }
}

// --- Decryption Logic ---
fn decrypt_file() {
    println!("\n--- Decrypt File ---");

    // 1. List available .txt files
    let mut available_files: Vec<String> = Vec::new();
    match fs::read_dir(".") { // "." means current directory
        Ok(entries) => {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(ext) = path.extension() {
                            if ext == "txt" { // Only list .txt files
                                if let Some(name_osstr) = path.file_name() {
                                    if let Some(name_str) = name_osstr.to_str() {
                                        available_files.push(name_str.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error reading directory: {}", e);
            return;
        }
    }

    if available_files.is_empty() {
        println!("No .txt files found in the current directory to decrypt.");
        return;
    }

    println!("Available files to decrypt:");
    for (i, filename) in available_files.iter().enumerate() {
        println!("{}. {}", i + 1, filename);
    }

    // 2. User selects file
    let file_index: usize;
    loop {
        print!("Enter number of the file to decrypt: ");
        io::stdout().flush().unwrap();
        let mut choice_input = String::new();
        io::stdin().read_line(&mut choice_input).expect("Failed to read choice");
        match choice_input.trim().parse::<usize>() {
            Ok(num) if num > 0 && num <= available_files.len() => {
                file_index = num - 1; // 0-based index
                break;
            }
            _ => println!("Invalid choice. Please enter a number from the list."),
        }
    }
    let selected_filename = &available_files[file_index];

    // 3. Get secret key
    print!("Enter Secret Key for '{}': ", selected_filename);
    io::stdout().flush().unwrap();
    let mut secret_key_input = String::new();
    io::stdin().read_line(&mut secret_key_input).expect("Failed to read secret key line");
    let secret_key = secret_key_input.trim();

    if secret_key.is_empty() {
        println!("Secret key cannot be empty for decryption. Aborting.");
        return;
    }
    let key_bytes = secret_key.as_bytes();

    // 4. Read file content (expecting only hex string)
    match fs::read_to_string(selected_filename) {
        Ok(hex_content) => {
            let trimmed_hex_content = hex_content.trim(); // Ensure no newlines from file read affect parsing
            if trimmed_hex_content.is_empty() {
                println!("File '{}' is empty. Cannot decrypt.", selected_filename);
                return;
            }
            // 5. Convert hex to bytes
            match hex_string_to_bytes(trimmed_hex_content) {
                Ok(encrypted_bytes_from_file) => {
                    // 6. Decrypt bytes
                    let decrypted_bytes = xor_cipher(&encrypted_bytes_from_file, key_bytes);

                    // 7. Print decrypted string
                    match String::from_utf8(decrypted_bytes) {
                        Ok(decrypted_string) => {
                            println!("\n--- Decrypted Content from {} ---", selected_filename);
                            println!("{}", decrypted_string);
                        }
                        Err(_) => {
                            eprintln!("Failed to convert decrypted bytes to a valid UTF-8 string. The key might be incorrect or the data corrupted.");
                            // Optionally, print the raw bytes as hex if UTF-8 fails
                            print!("Decrypted bytes (Hex, as fallback): ");
                            for byte in &encrypted_bytes_from_file { // This should be decrypted_bytes from xor_cipher
                                print!("{:02x}", byte);
                            }
                            println!();
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error converting hex data from file '{}': {}", selected_filename, e);
                }
            }
        }
        Err(e) => {
            eprintln!("Error reading file '{}': {}", selected_filename, e);
        }
    }
}

// --- Main Application Loop ---
fn main() {
    println!("Simple XOR Encryption/Decryption Tool");

    loop {
        println!("\nChoose an action:");
        println!("  1. Encrypt and Save Data");
        println!("  2. Decrypt File");
        println!("  3. Quit");
        print!("Enter your choice (1-3): ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed to read choice");

        match choice.trim() {
            "1" => encrypt_and_save_data(),
            "2" => decrypt_file(),
            "3" => {
                println!("Exiting program.");
                break;
            }
            _ => println!("Invalid choice. Please enter 1, 2, or 3."),
        }
    }
}