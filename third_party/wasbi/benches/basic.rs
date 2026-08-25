use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wasbi::prelude::*;

const HEADER: &[u8] = &[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

/// Module: (func (export "f") (result i32) i32.const 42)
fn module_const_42() -> Vec<u8> {
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F]);
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]);
    buf.extend_from_slice(&[0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B]);
    buf
}

/// Module with a loop that counts down from N.
fn module_countdown() -> Vec<u8> {
    let mut buf = Vec::from(HEADER);
    // Type: (i32) -> (i32)
    buf.extend_from_slice(&[0x01, 0x06, 0x01, 0x60, 0x01, 0x7F, 0x01, 0x7F]);
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]);
    // Body: loop { local.get 0; i32.const 1; i32.sub; local.tee 0; br_if 0 }; local.get 0
    let body: &[u8] = &[
        0x03, 0x40, // loop (void)
        0x20, 0x00, // local.get 0
        0x41, 0x01, // i32.const 1
        0x6B, // i32.sub
        0x22, 0x00, // local.tee 0
        0x0D, 0x00, // br_if 0
        0x0B, // end loop
        0x20, 0x00, // local.get 0
    ];
    let body_len = body.len() + 2;
    buf.push(0x0A);
    buf.push((body_len + 2) as u8);
    buf.push(0x01);
    buf.push(body_len as u8);
    buf.push(0x00);
    buf.extend_from_slice(body);
    buf.push(0x0B);
    buf
}

/// Fibonacci module: (func (export "fib") (param i32) (result i32) ...)
fn module_fibonacci() -> Vec<u8> {
    let mut buf = Vec::from(HEADER);
    // Type: (i32) -> (i32)
    buf.extend_from_slice(&[0x01, 0x06, 0x01, 0x60, 0x01, 0x7F, 0x01, 0x7F]);
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    buf.extend_from_slice(&[0x07, 0x07, 0x01, 0x03, b'f', b'i', b'b', 0x00, 0x00]);
    // Body: iterative fib using locals
    // local a=0, b=1, i=0
    // loop: if i >= n { return a }; tmp=a+b; a=b; b=tmp; i++; br loop
    let body: &[u8] = &[
        // 3 locals: a(i32), b(i32), i(i32)
        0x20, 0x00, // local.get 0 (n)
        0x41, 0x02, // i32.const 2
        0x49, // i32.lt_s
        0x04, 0x7F, // if (result i32)
        0x20, 0x00, //   local.get 0
        0x05, // else
        0x41, 0x00, //   i32.const 0 -> a
        0x21, 0x01, //   local.set 1
        0x41, 0x01, //   i32.const 1 -> b
        0x21, 0x02, //   local.set 2
        0x41, 0x02, //   i32.const 2 -> i
        0x21, 0x03, //   local.set 3
        0x03, 0x40, //   loop
        0x20, 0x01, //     local.get 1 (a)
        0x20, 0x02, //     local.get 2 (b)
        0x6A, //     i32.add -> tmp
        0x20, 0x02, //     local.get 2 (b)
        0x21, 0x01, //     local.set 1 (a = old b)
        0x21, 0x02, //     local.set 2 (b = tmp)
        0x20, 0x03, //     local.get 3 (i)
        0x41, 0x01, //     i32.const 1
        0x6A, //     i32.add
        0x22, 0x03, //     local.tee 3
        0x20, 0x00, //     local.get 0 (n)
        0x49, //     i32.lt_s
        0x0D, 0x00, //     br_if 0
        0x0B, //   end loop
        0x20, 0x02, //   local.get 2 (b)
        0x0B, // end if
    ];
    let locals: &[u8] = &[0x01, 0x03, 0x7F]; // 1 group of 3 locals of type i32
    let func_body_len = locals.len() + body.len() + 1; // +1 for end
    buf.push(0x0A);
    buf.push((func_body_len + 2) as u8); // section size = body count + body size leb + body
    buf.push(0x01); // one body
    buf.push(func_body_len as u8);
    buf.extend_from_slice(locals);
    buf.extend_from_slice(body);
    buf.push(0x0B); // end

    buf
}

fn bench_decode(c: &mut Criterion) {
    let wasm = module_const_42();
    c.bench_function("decode_minimal", |b| {
        b.iter(|| wasbi::decoder::decode(black_box(&wasm)).unwrap())
    });
}

fn bench_validate(c: &mut Criterion) {
    let wasm = module_const_42();
    let module = wasbi::decoder::decode(&wasm).unwrap();
    c.bench_function("validate_minimal", |b| {
        b.iter(|| wasbi::validator::validate(black_box(&module)).unwrap())
    });
}

fn bench_module_new(c: &mut Criterion) {
    let wasm = module_const_42();
    let engine = Engine::default();
    c.bench_function("module_new", |b| {
        b.iter(|| Module::new(&engine, black_box(&wasm)).unwrap())
    });
}

fn bench_instantiate(c: &mut Criterion) {
    let wasm = module_const_42();
    let engine = Engine::default();
    c.bench_function("instantiate", |b| {
        b.iter(|| {
            let module = Module::new(&engine, &wasm).unwrap();
            Instance::new(module, &engine).unwrap()
        })
    });
}

fn bench_call_const(c: &mut Criterion) {
    let wasm = module_const_42();
    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();
    c.bench_function("call_const_42", |b| {
        b.iter(|| {
            instance.set_fuel(1000);
            instance.call("f", &[])
        })
    });
}

fn bench_countdown(c: &mut Criterion) {
    let wasm = module_countdown();
    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    let mut group = c.benchmark_group("countdown");
    for n in [100, 1_000, 10_000] {
        group.bench_function(format!("n={n}"), |b| {
            b.iter(|| {
                instance.set_fuel(1_000_000);
                instance.call("f", &[Value::I32(n)])
            })
        });
    }
    group.finish();
}

fn bench_fibonacci(c: &mut Criterion) {
    let wasm = module_fibonacci();
    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    let mut group = c.benchmark_group("fibonacci");
    for n in [10, 20, 30] {
        group.bench_function(format!("n={n}"), |b| {
            b.iter(|| {
                instance.set_fuel(1_000_000);
                instance.call("fib", &[Value::I32(n)])
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_decode,
    bench_validate,
    bench_module_new,
    bench_instantiate,
    bench_call_const,
    bench_countdown,
    bench_fibonacci,
);
criterion_main!(benches);
