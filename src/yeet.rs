// Jackson Coxson
// Proof of concept for Secret Tunnel

use std::{io::Write, net::SocketAddrV4};

mod event;
mod handle;
mod packets;
mod wireguard;

// I don't want this to be async to try and get as much performance as possible
// We are limited by how fast we can yeet packets back and forth
fn main() {
    println!("Starting server");

    let wg = wireguard::Wireguard::new(SocketAddrV4::new(
        std::net::Ipv4Addr::new(0, 0, 0, 0),
        51820,
    ));

    // Create TCP listener
    let listener = std::net::TcpListener::bind("0.0.0.0:3000").unwrap();
    let (send_ready, ready) = crossbeam_channel::bounded(0);

    // A place to store the test data
    let tests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let spawn_tests = tests.clone();

    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();

        // Create test data
        let mut local_tests = Vec::new();
        for _ in 0..100 {
            let mut test = Vec::new();
            for _ in 0..256 {
                test.push(rand::random::<u8>());
            }
            tests.lock().unwrap().push(test.clone());
            local_tests.push(test);
        }

        // Wait until we're ready to send the test
        ready.recv().unwrap();

        // Send the test data
        for test in local_tests {
            println!("Writing test {}", test[test.len() - 1]);
            stream.write_all(&test).unwrap();
            std::thread::sleep(std::time::Duration::from_nanos(1));
        }
    });

    // Wait until the user presses enter
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    println!("{}", input);

    let handle = wg.tcp_connect(3000).unwrap();
    send_ready.send(()).unwrap();

    // Collect the test data
    let mut collected_tests = Vec::new();

    let current_time = std::time::Instant::now();

    loop {
        match handle.recv().unwrap() {
            event::Event::Transport(_, data) => {
                println!("{:?}", data);
                collected_tests.push(data);
                continue;
            }
            event::Event::Closed => {
                break;
            }
            _ => {
                continue;
            }
        };
    }

    println!("Elapsed time: {:?}", current_time.elapsed());
    println!(
        "MB/s: {:?}",
        collected_tests.len() as f64 / current_time.elapsed().as_secs_f64()
    );

    // Concatenate collected tests
    let mut concatenated_received = Vec::new();
    for test in collected_tests {
        concatenated_received.extend_from_slice(&test);
    }

    // Concatenate generated tests
    let mut concatenated_sent = Vec::new();
    for test in spawn_tests.lock().unwrap().iter() {
        concatenated_sent.extend_from_slice(test);
    }

    // Compare the two
    assert_eq!(concatenated_sent, concatenated_received);

    println!("All tests passed");
}
