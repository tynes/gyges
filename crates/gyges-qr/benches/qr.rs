//! Keystone QR timings for `docs/testing.md` §9: splitting a PCZT into
//! animated `ur:` frames, rendering them, detecting a code in a camera
//! frame, and reassembling the message. These run in the CLI, not the
//! daemon.
//!
//! ```console
//! cargo bench -p gyges-qr --bench qr
//! ```

use std::time::Duration;

use criterion::{Criterion, SamplingMode, Throughput, criterion_group, criterion_main};
use gyges_qr::{Assembler, DEFAULT_FRAGMENT_LEN, LumaFrame, Payload, render_frame, scan};
use qrcode::{Color, EcLevel, QrCode};

/// A PCZT-sized message (a two-action Ironwood PCZT is some 10 KB),
/// deterministic.
fn message(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9e37_79b9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// One 1280×720 grey frame with `text`'s code at 4 pixels a module.
fn camera_frame(text: &str) -> LumaFrame {
    let (w, h, scale, x0, y0) = (1280usize, 720usize, 4usize, 300usize, 120usize);
    let code = QrCode::with_error_correction_level(text.to_ascii_uppercase(), EcLevel::L).unwrap();
    let n = code.width();
    let mut data = vec![110u8; w * h];
    let quiet = 4 * scale;
    for y in y0 - quiet..y0 + n * scale + quiet {
        for x in x0 - quiet..x0 + n * scale + quiet {
            data[y * w + x] = 235;
        }
    }
    for (i, c) in code.to_colors().iter().enumerate() {
        if *c == Color::Dark {
            let (mx, my) = (i % n, i / n);
            for dy in 0..scale {
                for dx in 0..scale {
                    data[(y0 + my * scale + dy) * w + x0 + mx * scale + dx] = 20;
                }
            }
        }
    }
    LumaFrame {
        width: w,
        height: h,
        data,
    }
}

fn qr(c: &mut Criterion) {
    let pczt = Payload::Pczt(message(10_000));
    let frames = pczt
        .frames(DEFAULT_FRAGMENT_LEN)
        .unwrap()
        .take_loops(1)
        .unwrap();
    eprintln!("10 KB PCZT: {} frames", frames.len());

    let mut g = c.benchmark_group("keystone-qr");
    g.sample_size(20);
    g.sampling_mode(SamplingMode::Flat);
    g.measurement_time(Duration::from_secs(8));
    g.throughput(Throughput::Elements(frames.len() as u64));
    g.bench_function("frames/10kb-pczt", |b| {
        b.iter(|| {
            pczt.frames(DEFAULT_FRAGMENT_LEN)
                .unwrap()
                .take_loops(1)
                .unwrap()
        })
    });
    g.bench_function("render/10kb-pczt", |b| {
        b.iter(|| {
            frames
                .iter()
                .map(|f| render_frame(f).unwrap().len())
                .sum::<usize>()
        })
    });
    g.bench_function("assemble/10kb-pczt", |b| {
        b.iter(|| {
            let mut asm = Assembler::new();
            for f in &frames {
                asm.receive(f).unwrap();
            }
            assert!(asm.is_complete());
            Payload::from_assembler(&asm).unwrap().unwrap()
        })
    });
    g.throughput(Throughput::Elements(1));
    let shot = camera_frame(&frames[0]);
    assert_eq!(scan::decode(&shot).len(), 1, "the frame decodes");
    g.bench_function("detect/720p-frame", |b| b.iter(|| scan::decode(&shot)));
    g.finish();
}

criterion_group!(benches, qr);
criterion_main!(benches);
