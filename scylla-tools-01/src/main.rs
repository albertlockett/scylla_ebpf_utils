use aya::{
    maps::perf::AsyncPerfEventArray,
    Bpf, 
    util::online_cpus,
    include_bytes_aligned
};
use aya::programs::KProbe;
use bytes::BytesMut;
use std::{
    convert::{TryFrom,TryInto},
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};
use structopt::StructOpt;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use aya_log::BpfLogger;
use tokio::{signal, task};

use scylla_tools_01_common::FileEvent;


#[tokio::main]
async fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    
}

fn try_main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    // This will include youe eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/scylla-tools-01"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/scylla-tools-01"
    ))?;

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Debug)
            .set_location_level(LevelFilter::Debug)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();
    BpfLogger::init(&mut bpf).unwrap();

    let program: &mut KProbe = bpf.program_mut("scylla_tools_01").unwrap().try_into()?;
    program.load()?;
    program.attach("do_sys_openat2", 0)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const FileEvent;
                    let data = unsafe { ptr.read_unaligned() };
                    let fname = std::str::from_utf8(&data.filename).unwrap();
                    println!("LOG: CPUID {}, PID {}, fname {}", cpu_id, data.pid, fname);
                }
            }
        });
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    println!("Waiting for Ctrl-C...");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(500))
    }
    println!("Exiting...");

    Ok(())
}
