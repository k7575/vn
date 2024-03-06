
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;

use pnet::packet::ipv4::Ipv4Packet;
use std::io::Write;
use std::net::UdpSocket;
use std::os::fd::FromRawFd;
use std::process::exit;
use std::{fs::File, io::Read};
use clap::Parser;

mod tun;

const BUFSIZE: usize = 1516;
const BLKSIZE: usize = 16;
const KEYSIZE: usize = 32;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    local: String,
    #[arg(short, long)]
    remote: String,
    #[arg(short, long)]
    key: String,
}

fn main() {
    let args = Args::parse();
    if args.key.len() < KEYSIZE {
        println!("error: key size {} bytes", KEYSIZE);
        exit(1);
    }


    let fd = tun::new().unwrap();
    let f = unsafe { File::from_raw_fd(fd) };

    let a: [u8; KEYSIZE] = args.key.as_bytes()[..KEYSIZE].try_into().unwrap();
    let key = GenericArray::from(a);
    let k = Aes256::new(&key);
    f1(f, k, args.local.as_str(), args.remote.as_str()).unwrap();
}


fn f1(mut f: File, k: Aes256, local: &str, remote: &str) -> Result<(), Box<dyn std::error::Error>> {
    let tx = UdpSocket::bind(local)?;
    let rx = tx.try_clone()?;
    let k2 = k.clone();
    let mut f2 = f.try_clone()?;
    std::thread::spawn(move || {
        let mut buf = [0u8; BUFSIZE];
        loop {
            if let Ok(n) = rx.recv(&mut buf) {
                let mut offset = 0;
                while offset < n {
                    let block = GenericArray::from_mut_slice(&mut buf[offset..offset + BLKSIZE]);
                    k2.decrypt_block(block);
                    offset += BLKSIZE;
                }
                if let Err(e) = f2.write(&buf[..offset]){
                    dbg!(e);
                }
            }
        }
    });

    let mut buf = [0u8; BUFSIZE];
    loop {
        let n = f.read(&mut buf)?;
        if let Some(_ipv4_packet) = Ipv4Packet::new(&buf[..n]) {
            //let dest = ipv4_packet.get_destination();
            let mut offset = 0;
            while offset < n {
                let block = GenericArray::from_mut_slice(&mut buf[offset..offset + BLKSIZE]);
                k.encrypt_block(block);
                offset += BLKSIZE;
            }
            tx.send_to(&buf[..offset], remote)?;
        }
    }
}
