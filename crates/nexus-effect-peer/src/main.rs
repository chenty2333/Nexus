// SPDX-License-Identifier: MPL-2.0

fn main() {
    if let Err(error) = nexus_effect_peer::serve(std::io::stdin().lock(), std::io::stdout().lock())
    {
        eprintln!("nexus-effect-peer: {error}");
        std::process::exit(1);
    }
}
