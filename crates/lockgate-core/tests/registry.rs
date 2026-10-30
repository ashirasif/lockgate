//! The project registry: an index onto project directories, not a store of
//! engagement data.

use std::path::PathBuf;

use lockgate_core::Registry;

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("lockgate-reg-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

#[test]
fn creates_and_lists_projects() {
    let root = temp_dir("basic");
    let registry = Registry::open(&root.join("registry.db")).unwrap();

    let a = registry
        .create("alpha", &root.join("projects/alpha"), 100)
        .unwrap();
    let b = registry
        .create("beta", &root.join("projects/beta"), 200)
        .unwrap();

    // Creating a project must leave it immediately openable.
    assert!(a.path.join("project.db").exists());
    assert!(a.path.join("blobs").is_dir());

    // Ordered by recency of use, falling back to creation.
    let names: Vec<String> = registry
        .list()
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(names, vec!["beta", "alpha"]);

    registry.touch(a.id, 300).unwrap();
    let names: Vec<String> = registry
        .list()
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(names, vec!["alpha", "beta"], "touch should reorder");

    assert_eq!(registry.by_path(&b.path).unwrap().unwrap().id, b.id);
}

#[test]
fn re_registering_a_path_renames_rather_than_failing() {
    let root = temp_dir("rename");
    let registry = Registry::open(&root.join("registry.db")).unwrap();
    let dir = root.join("projects/thing");

    let first = registry.create("old name", &dir, 100).unwrap();
    let second = registry.create("new name", &dir, 200).unwrap();

    assert_eq!(first.id, second.id, "same path should be the same project");
    assert_eq!(second.name, "new name");
    assert_eq!(registry.list().unwrap().len(), 1);
}

/// Forgetting a project must not destroy the engagement's traffic.
#[test]
fn forget_leaves_the_directory_alone() {
    let root = temp_dir("forget");
    let registry = Registry::open(&root.join("registry.db")).unwrap();
    let project = registry
        .create("doomed", &root.join("projects/doomed"), 100)
        .unwrap();

    registry.forget(project.id).unwrap();

    assert!(registry.list().unwrap().is_empty());
    assert!(
        project.path.join("project.db").exists(),
        "forget must not delete data on disk"
    );
}

/// A program groups several target projects under one policy umbrella.
#[test]
fn programs_group_targets() {
    let root = temp_dir("program");
    let registry = Registry::open(&root.join("registry.db")).unwrap();
    let acme = registry
        .create("acme", &root.join("projects/acme"), 100)
        .unwrap();
    let acme_eu = registry
        .create("acme-eu", &root.join("projects/acme-eu"), 101)
        .unwrap();

    let id = registry
        .create_program(
            "Acme VDP",
            Some("No automated scanning without a rate ceiling."),
            200,
        )
        .unwrap();

    registry.add_program_target(id, acme.id).unwrap();
    registry.add_program_target(id, acme_eu.id).unwrap();
    // Re-adding is a no-op, not a duplicate.
    registry.add_program_target(id, acme.id).unwrap();

    let targets = registry.program_targets(id).unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].name, "acme");
    assert_eq!(targets[1].name, "acme-eu");

    registry.set_program_policy(id, None).unwrap();
    assert_eq!(registry.program(id).unwrap().unwrap().policy_md, None);

    // Removing a target unlinks it; deleting the program keeps the projects.
    registry.remove_program_target(id, acme.id).unwrap();
    assert_eq!(registry.program_targets(id).unwrap().len(), 1);
    registry.delete_program(id).unwrap();
    assert!(registry.programs().unwrap().is_empty());
    assert_eq!(
        registry.list().unwrap().len(),
        2,
        "projects outlive their program"
    );

    // Names are unique — the orchestrator addresses programs by name.
    registry.create_program("Dup", None, 300).unwrap();
    assert!(registry.create_program("Dup", None, 301).is_err());
}
