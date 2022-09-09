// Authored by Jackson Coxson

pub mod bindings;
pub mod event;
pub mod handle;
pub mod packets;
pub mod wireguard;

#[cfg(feature = "minimuxer")]
pub mod bundle;

#[cfg(test)]
mod tests {
    use byteorder::{ReadBytesExt, WriteBytesExt};
    use std::{io::Write, net::SocketAddrV4};

    use crate::{event, wireguard};

    #[test]
    fn endurance_test() {
        base_test(100_000, 256);
    }

    #[test]
    fn chonk_test() {
        base_test(100, 100_000);
    }

    #[test]
    fn ping_test() {
        let wg = wireguard::Wireguard::new(SocketAddrV4::new(
            std::net::Ipv4Addr::new(0, 0, 0, 0),
            51820,
        ));
        println!("Wireguard ready");

        // Create a TCP listener
        let listener = std::net::TcpListener::bind("0.0.0.0:3000").unwrap();

        std::thread::spawn(move || {
            let mut position = 0;
            let mut response_times = vec![];

            let (mut socket, _) = listener.accept().unwrap();

            while position < 255 {
                let time = std::time::Instant::now();
                // Send the current position
                socket.write_u8(position).unwrap();

                // Read the next position
                let next = socket.read_u8().unwrap();
                assert!(next == position + 1);
                position = next;
                response_times.push(time.elapsed());
            }
            let total_time: u128 = response_times.iter().map(|t| t.as_micros()).sum();

            println!(
                "Average response time: {:?} microseconds",
                total_time as u32 / response_times.len() as u32
            );
        });

        // Ping the server
        let _ = std::process::Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg("10.7.0.1")
            .spawn();

        let handle = wg.tcp_connect(3000).unwrap();

        loop {
            match handle.recv().unwrap() {
                event::Event::Transport(_, data) => {
                    let position = data[0];
                    handle.send(vec![position + 1]).unwrap();
                }
                event::Event::Closed(_) => {
                    break;
                }
                _ => {
                    continue;
                }
            }
        }
    }

    #[test]
    fn control() {
        // Create the tests
        let mut tests = Vec::new();
        for _ in 0..100 {
            let mut test = Vec::new();
            for _ in 0..256 {
                test.push(rand::random::<u8>());
            }
            tests.push(test);
        }
        let tests_to_send = tests.clone();
        let listener = std::net::TcpListener::bind("0.0.0.0:3000").unwrap();
        let mut socket = std::net::TcpStream::connect("127.0.0.1:3000").unwrap();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            for test in tests_to_send {
                stream.write_all(&test).unwrap();
            }
        });

        let mut collected_tests = Vec::new();
        while let Ok(u) = socket.read_u8() {
            collected_tests.push(u);
        }

        let mut combined_tests = Vec::new();
        for i in tests {
            for o in i {
                combined_tests.push(o);
            }
        }

        assert_eq!(combined_tests, collected_tests);
        println!("All tests passed");
    }

    #[test]
    fn local_stop() {
        let thread = std::thread::spawn(|| {
            // Create TCP server
            let listener = std::net::TcpListener::bind("0.0.0.0:3000").unwrap();
            let (mut stream, _) = listener.accept().unwrap();

            let mut buf = vec![];
            match std::io::Read::read_to_end(&mut stream, &mut buf) {
                Ok(_) => {}
                Err(e) => panic!("{e}"),
            }
        });
        let wg = wireguard::Wireguard::new(SocketAddrV4::new(
            std::net::Ipv4Addr::new(0, 0, 0, 0),
            51820,
        ));

        let handle = wg.tcp_connect(3000).unwrap();
        handle.close();

        thread.join().unwrap();
    }

    #[test]
    fn lockdownd() {
        let wg = wireguard::Wireguard::new((std::net::Ipv4Addr::new(0, 0, 0, 0), 51820));

        let handle = wg.tcp_connect(62078).unwrap();

        let to_send: Vec<u8> = vec![
            60, 63, 120, 109, 108, 32, 118, 101, 114, 115, 105, 111, 110, 61, 34, 49, 46, 48, 34,
            32, 101, 110, 99, 111, 100, 105, 110, 103, 61, 34, 85, 84, 70, 45, 56, 34, 63, 62, 10,
            60, 33, 68, 79, 67, 84, 89, 80, 69, 32, 112, 108, 105, 115, 116, 32, 80, 85, 66, 76,
            73, 67, 32, 34, 45, 47, 47, 65, 112, 112, 108, 101, 47, 47, 68, 84, 68, 32, 80, 76, 73,
            83, 84, 32, 49, 46, 48, 47, 47, 69, 78, 34, 32, 34, 104, 116, 116, 112, 58, 47, 47,
            119, 119, 119, 46, 97, 112, 112, 108, 101, 46, 99, 111, 109, 47, 68, 84, 68, 115, 47,
            80, 114, 111, 112, 101, 114, 116, 121, 76, 105, 115, 116, 45, 49, 46, 48, 46, 100, 116,
            100, 34, 62, 10, 60, 112, 108, 105, 115, 116, 32, 118, 101, 114, 115, 105, 111, 110,
            61, 34, 49, 46, 48, 34, 62, 10, 60, 100, 105, 99, 116, 62, 10, 9, 60, 107, 101, 121,
            62, 76, 97, 98, 101, 108, 60, 47, 107, 101, 121, 62, 10, 9, 60, 115, 116, 114, 105,
            110, 103, 62, 105, 100, 101, 118, 105, 99, 101, 105, 110, 102, 111, 60, 47, 115, 116,
            114, 105, 110, 103, 62, 10, 9, 60, 107, 101, 121, 62, 82, 101, 113, 117, 101, 115, 116,
            60, 47, 107, 101, 121, 62, 10, 9, 60, 115, 116, 114, 105, 110, 103, 62, 81, 117, 101,
            114, 121, 84, 121, 112, 101, 60, 47, 115, 116, 114, 105, 110, 103, 62, 10, 60, 47, 100,
            105, 99, 116, 62, 10, 60, 47, 112, 108, 105, 115, 116, 62, 10,
        ];

        let len: u32 = to_send.len() as u32;
        let len = len.to_be_bytes().to_vec();

        handle.send(len).unwrap();

        handle.send(to_send).unwrap();

        let res = handle.recv().unwrap();
        println!("{:02X?}", res);

        let res = handle.recv().unwrap();
        println!("{:02X?}", res);

        let res = match res {
            event::Event::Transport(_, b) => b,
            _ => {
                panic!()
            }
        };

        assert_eq!(
            res,
            vec![
                60, 63, 120, 109, 108, 32, 118, 101, 114, 115, 105, 111, 110, 61, 34, 49, 46, 48,
                34, 32, 101, 110, 99, 111, 100, 105, 110, 103, 61, 34, 85, 84, 70, 45, 56, 34, 63,
                62, 10, 60, 33, 68, 79, 67, 84, 89, 80, 69, 32, 112, 108, 105, 115, 116, 32, 80,
                85, 66, 76, 73, 67, 32, 34, 45, 47, 47, 65, 112, 112, 108, 101, 47, 47, 68, 84, 68,
                32, 80, 76, 73, 83, 84, 32, 49, 46, 48, 47, 47, 69, 78, 34, 32, 34, 104, 116, 116,
                112, 58, 47, 47, 119, 119, 119, 46, 97, 112, 112, 108, 101, 46, 99, 111, 109, 47,
                68, 84, 68, 115, 47, 80, 114, 111, 112, 101, 114, 116, 121, 76, 105, 115, 116, 45,
                49, 46, 48, 46, 100, 116, 100, 34, 62, 10, 60, 112, 108, 105, 115, 116, 32, 118,
                101, 114, 115, 105, 111, 110, 61, 34, 49, 46, 48, 34, 62, 10, 60, 100, 105, 99,
                116, 62, 10, 9, 60, 107, 101, 121, 62, 82, 101, 113, 117, 101, 115, 116, 60, 47,
                107, 101, 121, 62, 10, 9, 60, 115, 116, 114, 105, 110, 103, 62, 81, 117, 101, 114,
                121, 84, 121, 112, 101, 60, 47, 115, 116, 114, 105, 110, 103, 62, 10, 9, 60, 107,
                101, 121, 62, 84, 121, 112, 101, 60, 47, 107, 101, 121, 62, 10, 9, 60, 115, 116,
                114, 105, 110, 103, 62, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 109, 111, 98,
                105, 108, 101, 46, 108, 111, 99, 107, 100, 111, 119, 110, 60, 47, 115, 116, 114,
                105, 110, 103, 62, 10, 60, 47, 100, 105, 99, 116, 62, 10, 60, 47, 112, 108, 105,
                115, 116, 62, 10
            ]
        )
    }

    fn base_test(num: usize, size: usize) {
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
            for _ in 0..num {
                let mut test = Vec::new();
                for _ in 0..size {
                    test.push(rand::random::<u8>());
                }
                tests.lock().unwrap().push(test.clone());
                local_tests.push(test);
            }

            // Wait until we're ready to send the test
            ready.recv().unwrap();

            // Send the test data
            for test in local_tests {
                stream.write_all(&test).unwrap();
                std::thread::sleep(std::time::Duration::from_nanos(1));
            }
        });

        // Ping the server
        let _ = std::process::Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg("10.7.0.1")
            .spawn();

        let handle = wg.tcp_connect(3000).unwrap();
        send_ready.send(()).unwrap();

        // Collect the test data
        let mut collected_tests = Vec::new();

        let current_time = std::time::Instant::now();

        loop {
            match handle.recv().unwrap() {
                event::Event::Transport(_, data) => {
                    collected_tests.push(data);
                    continue;
                }
                event::Event::Closed(_) => {
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
        println!("Testing length");
        assert_eq!(concatenated_sent.len(), concatenated_received.len());
        println!("Testing contents");
        assert_eq!(concatenated_sent, concatenated_received);

        println!("All tests passed");

        drop(wg);
        std::thread::sleep(std::time::Duration::from_millis(500))
    }
}
