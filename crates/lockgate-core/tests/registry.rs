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
