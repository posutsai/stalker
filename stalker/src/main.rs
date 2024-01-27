use anyhow::Context;
use aya::maps::AsyncPerfEventArray;
use aya::programs::UProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{debug, info, warn};
use stalker_common::SQLExecution;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

const DATABASE_EXECUTABLE_PATH: &str = "/usr/lib/postgresql/16/bin/postgres";
fn attach_parser_probe(bpf_artifact: &mut Bpf) -> Result<(), anyhow::Error> {
    let parser_probe: &mut UProbe = bpf_artifact
        .program_mut("execute_sql_statement")
        .unwrap()
        .try_into()?;
    parser_probe.load()?;
    // Reference
    // 1. postgres_internals-14 p.290
    // 2. https://github.com/postgres/postgres/blob/bc397e5cdb31c399392d693cbc5909341d21235a/src/backend/tcop/postgres.c#L1012
    parser_probe.attach(Some("raw_parser"), 0, DATABASE_EXECUTABLE_PATH, None)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf_artifact = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/stalker"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_artifact = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/stalker"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf_artifact) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    attach_parser_probe(&mut bpf_artifact)?;
    let mut perf_array = AsyncPerfEventArray::try_from(bpf_artifact.take_map("EVENTS").unwrap())?;

    // Calculate the size of the Data structure in bytes.
    let len_of_data = std::mem::size_of::<SQLExecution>();
    // Iterate over each online CPU core. For eBPF applications, processing is often done per CPU core.
    for cpu_id in online_cpus()? {
        // open a separate perf buffer for each cpu
        let mut buf = perf_array.open(cpu_id, Some(32))?;

        // process each perf buffer in a separate task
        tokio::spawn(async move {
            // Prepare a set of buffers to store the data read from the perf buffer.
            // Here, 10 buffers are created, each with a capacity equal to the size of the Data structure.
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(len_of_data))
                .collect::<Vec<_>>();

            loop {
                // Attempt to read events from the perf buffer into the prepared buffers.
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        warn!("Error reading events: {}", e);
                        continue;
                    }
                };

                // Iterate over the number of events read. `events.read` indicates how many events were read.
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let data = buf.as_ptr() as *const SQLExecution; // Cast the buffer pointer to a Data pointer.
                    info!("{}", unsafe { *data });
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
