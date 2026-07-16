//! THROWAWAY PROTOTYPE for issue #223; do not use from the production runtime.
//!
//! Question: does Client-advertised receive/start capacity give Server enough
//! state to assign immediately, withdraw placement during drain, and re-place
//! a Visitor once before backend setup starts?
//!
//! Run with `cargo run --example h3_receive_slots_prototype`.

use std::io::{self, Write};

#[derive(Default)]
struct State {
    advertised_slots: usize,
    assigned_unstarted: usize,
    active_visitors: usize,
    draining: bool,
    replaced_once: usize,
}

impl State {
    fn advertise(&mut self) {
        if !self.draining {
            self.advertised_slots += 1;
        }
    }

    fn assign_visitor(&mut self) {
        if !self.draining && self.advertised_slots > 0 {
            self.advertised_slots -= 1;
            self.assigned_unstarted += 1;
        }
    }

    fn begin_backend(&mut self) {
        if self.assigned_unstarted > 0 {
            self.assigned_unstarted -= 1;
            self.active_visitors += 1;
        }
    }

    fn re_place_unstarted(&mut self) {
        if self.assigned_unstarted > 0 && self.replaced_once == 0 && !self.draining {
            self.assigned_unstarted -= 1;
            self.replaced_once = 1;
            self.assign_visitor();
        }
    }

    fn drain(&mut self) {
        self.draining = true;
        self.advertised_slots = 0;
    }
}

fn main() -> io::Result<()> {
    let mut state = State::default();
    loop {
        render(&state);
        print!("action: ");
        io::stdout().flush()?;

        let mut action = String::new();
        if io::stdin().read_line(&mut action)? == 0 {
            return Ok(());
        }
        match action.trim() {
            "a" => state.advertise(),
            "v" => state.assign_visitor(),
            "b" => state.begin_backend(),
            "r" => state.re_place_unstarted(),
            "d" => state.drain(),
            "q" => return Ok(()),
            _ => {}
        }
    }
}

fn render(state: &State) {
    print!("\x1b[2J\x1b[H");
    println!("\x1b[1mTHROWAWAY H3 receive-slot state model\x1b[0m");
    println!("advertised_slots:     {}", state.advertised_slots);
    println!("assigned_unstarted:   {}", state.assigned_unstarted);
    println!("active_visitors:      {}", state.active_visitors);
    println!("draining:             {}", state.draining);
    println!("replaced_once:        {}", state.replaced_once);
    println!();
    println!("\x1b[1m[a]\x1b[0m advertise slot  \x1b[1m[v]\x1b[0m Visitor arrives");
    println!("\x1b[1m[b]\x1b[0m backend starts    \x1b[1m[r]\x1b[0m re-place unstarted");
    println!("\x1b[1m[d]\x1b[0m drain/withdraw    \x1b[1m[q]\x1b[0m quit");
}
