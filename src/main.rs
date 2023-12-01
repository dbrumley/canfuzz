use can_dbc::{ByteOrder, Message, Signal, DBC};
use clap::{App, Arg};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
//use socketcan::{CANFrame, CANSocket};
use std::fs::File;
use std::io::Read;

fn read_dbc_file(file_path: &str) -> DBC {
    let mut file = File::open(file_path).expect("Unable to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Unable to read file");
    DBC::from_slice(&contents.as_bytes()).expect("Unable to parse DBC file")
}

fn fuzz_signal(signal: &Signal, rng: &mut StdRng) -> u64 {
    let signal_size = signal.signal_size;
    rng.gen_range(0..2u64.pow(signal_size as u32))
}

fn fuzz_can_frame(message: &Message, rng: &mut StdRng) -> Vec<u8> {
    let mut frame_data = vec![0u8; *message.message_size() as usize];

    for signal in message.signals() {
        let fuzzed_value = fuzz_signal(signal, rng);

        let start_bit = signal.start_bit;
        let end_bit = start_bit + signal.signal_size - 1;
        let start_byte = start_bit / 8;
        let end_byte = end_bit / 8;

        if (end_byte as usize) >= frame_data.len() {
            continue; // Skip this signal or handle the error appropriately
        }

        if start_byte == end_byte {
            // Signal fits within a single byte
            let bit_mask = ((1 << signal.signal_size) - 1) << (start_bit % 8);
            frame_data[start_byte as usize] |=
                (fuzzed_value << (start_bit % 8)) as u8 & bit_mask as u8;
        } else {
            // Signal spans multiple bytes
            for i in start_byte..=end_byte {
                let byte_pos = i * 8;
                let shift_amount = match signal.byte_order() {
                    ByteOrder::LittleEndian => i8::try_from(start_bit).unwrap() - byte_pos as i8,
                    ByteOrder::BigEndian => byte_pos as i8 - i8::try_from(end_bit).unwrap(),
                };

                let value_to_insert = if shift_amount >= 0 {
                    (fuzzed_value >> shift_amount) as u8
                } else {
                    (fuzzed_value << -shift_amount) as u8
                };

                frame_data[i as usize] |= value_to_insert;
            }
        }
    }

    frame_data
}

fn fuzz_iteration(
    dbc: &DBC,
    rng: &mut StdRng,
    /* can_socket: Option<&CANSocket>, */ is_debug: bool,
) {
    for message in dbc.messages() {
        let fuzzed_message = fuzz_can_frame(&message, rng);

        if is_debug {
            println!(
                "Fuzzed Message for ID {} ({}): {:?}",
                message.message_name(),
                message.message_id().0,
                fuzzed_message
            );
        } else {
            /* } else if let Some(socket) = can_socket {
                // Construct and send the CAN frame
                let id = message.message_id().0;
                let data = &fuzzed_message; // Data should be &[u8]

                if let Ok(frame) = CANFrame::new(id, data, false, false) {
                    if let Err(e) = socket.write_frame(&frame) {
                        eprintln!("Failed to write frame to CAN bus: {}", e);
                    }
                } else {
                    eprintln!("Failed to construct CAN frame");
                }
            }*/
        }
    }

    // Update the RNG seed for the next iteration
    let new_seed: u64 = rng.gen();
    *rng = SeedableRng::seed_from_u64(new_seed);
}

fn main() {
    let matches = App::new("CAN Fuzzer")
        .version("0.1.0")
        .author("Your Name")
        .about("Fuzzes CAN messages based on a DBC file")
        .arg(
            Arg::with_name("DBC_FILE")
                .help("Sets the DBC file to use")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("seed")
                .long("seed")
                .value_name("SEED")
                .help("Sets a fixed seed for RNG")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("iterations")
                .long("iterations")
                .value_name("ITERATIONS")
                .help("Sets the number of fuzzing iterations, omit for continuous fuzzing")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .help("Enables debug mode to print messages instead of sending to CAN bus")
                .takes_value(false),
        )
        .get_matches();

    let dbc_file_path = matches.value_of("DBC_FILE").unwrap();
    let dbc = read_dbc_file(dbc_file_path);

    let seed = matches.value_of("seed").map_or_else(
        || rand::thread_rng().gen(),
        |s| s.parse().expect("Failed to parse seed as u64"),
    );

    let mut rng: StdRng = SeedableRng::seed_from_u64(seed);

    let is_debug = matches.is_present("debug");

    /* let can_socket = if !is_debug {
        // Replace "can0" with the appropriate interface name
        Some(CANSocket::open("can0").expect("Failed to open CAN socket"))
    } else {
        None
    }; */

    match matches.value_of("iterations") {
        Some(iter_str) => {
            let iterations: usize = iter_str
                .parse()
                .expect("Failed to parse iterations as usize");
            for _ in 0..iterations {
                fuzz_iteration(&dbc, &mut rng, is_debug);
            }
        }
        None => loop {
            fuzz_iteration(&dbc, &mut rng, is_debug);
        },
    }
}
