use cser_model::{Budget, Model, SupervisorId};

fn main() {
    let mut model = Model::new();
    let (scope, original) = model
        .create_scope(SupervisorId::new(1), Budget::new(8))
        .expect("create canonical scope");
    let effect = model
        .register(original, Budget::new(3))
        .expect("register canonical effect");
    model
        .prepare(original, effect)
        .expect("prepare canonical effect");

    model.crash(original).expect("crash original supervisor");
    model.fallback_pick(scope).expect("select kernel fallback");
    let replacement = model
        .rebind(scope, SupervisorId::new(2))
        .expect("complete replacement ready handshake");
    model
        .adopt(replacement, effect)
        .expect("adopt orphan prepared effect");
    model
        .commit(replacement, effect)
        .expect("commit adopted effect");
    model.complete(effect).expect("complete committed effect");
    model.check_invariants().expect("canonical trace is valid");

    for event in model.trace() {
        println!("{event:?}");
    }
}
