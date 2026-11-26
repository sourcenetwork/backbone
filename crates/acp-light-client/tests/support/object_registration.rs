use super::*;
use acp_light_client::{Actor, Object, ObjectRegistration};
use vera_modules::{
    acp::{
        types::{PolicyCmd, PolicyMarshalingType, PolicyNonce},
        AcpModule,
    },
    kv_store::ModuleKvStore,
};

fn object(id: &str) -> Object {
    Object {
        resource: "file".into(),
        id: id.into(),
    }
}

#[tokio::test]
async fn registration_reads_tell_live_archived_and_absent_objects_apart() {
    let mut module = AcpModule::new();
    let owner = "did:key:owner".parse().unwrap();
    let policy = module
        .create_policy(
            &owner,
            "name: documents\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
            PolicyNonce::default(),
        )
        .unwrap()
        .policy
        .id
        .to_string();
    let (live, archived, absent) = (object("report"), object("draft"), object("missing"));
    for registered in [&live, &archived] {
        module
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::RegisterObject(registered.clone()),
            )
            .unwrap();
    }
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::ArchiveObject(archived.clone()))
        .unwrap();
    let fixture = fixture_records(42, module.store().prefix_scan(b""));
    let timestamp = fixture.light.timestamp;
    let server = Server::start(fixture).await;
    let client = server.client();

    let read = |object: Object| {
        let client = client.clone();
        let policy = policy.clone();
        async move {
            client
                .read_current_object_registration(&policy, &object, HEIGHT)
                .await
        }
    };
    let (revision, registration) = read(live.clone()).await.unwrap();
    assert_eq!(revision.height, HEIGHT);
    assert_eq!(registration, ObjectRegistration::Live(Actor(owner.clone())));
    assert_eq!(
        read(archived.clone()).await.unwrap().1,
        ObjectRegistration::Archived
    );
    assert_eq!(
        client
            .read_current_object_owner(&policy, &archived, HEIGHT)
            .await
            .unwrap()
            .1,
        None
    );
    assert!(client
        .read_current_object_registration(&policy, &live, HEIGHT + 1)
        .await
        .is_err());

    let absent_prefix = vera_permission::object_owner_prefix(&policy, &absent).unwrap();
    *server.fixture.write() = build_fixture(
        42,
        module.store().prefix_scan(b""),
        timestamp,
        HEIGHT,
        0,
        Some((policy.clone(), absent_prefix)),
    );
    assert_eq!(read(absent).await.unwrap().1, ObjectRegistration::Absent);

    *server.fixture.write() =
        fixture_records_at(42, module.store().prefix_scan(b""), timestamp, HEIGHT);
    let (connected, headers) = super::policy_liveness::connect_current(&server).await;
    assert_eq!(
        connected
            .read_object_registration(&policy, &archived)
            .await
            .unwrap(),
        ObjectRegistration::Archived
    );
    assert_eq!(
        connected
            .read_object_registration(&policy, &live)
            .await
            .unwrap(),
        ObjectRegistration::Live(Actor(owner.clone()))
    );
    headers.abort();

    module.delete_policy(&owner, &policy).unwrap();
    *server.fixture.write() = fixture_records_at(
        42,
        module.store().prefix_scan(b""),
        timestamp + 1,
        HEIGHT + 1,
    );
    for retired in [live, archived] {
        assert_eq!(read(retired).await.unwrap().1, ObjectRegistration::Absent);
    }
}

#[tokio::test]
async fn registration_read_rejects_tampered_owner_evidence() {
    let mut module = AcpModule::new();
    let owner = "did:key:owner".parse().unwrap();
    let policy = module
        .create_policy(
            &owner,
            "name: documents\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
            PolicyNonce::default(),
        )
        .unwrap()
        .policy
        .id
        .to_string();
    let archived = object("draft");
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(archived.clone()))
        .unwrap();
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::ArchiveObject(archived.clone()))
        .unwrap();
    let prefix = vera_permission::object_owner_prefix(&policy, &archived).unwrap();
    let server = Server::start(fixture_records(42, module.store().prefix_scan(b""))).await;
    let client = server.client();
    assert_eq!(
        client
            .read_current_object_registration(&policy, &archived, HEIGHT)
            .await
            .unwrap()
            .1,
        ObjectRegistration::Archived
    );
    server
        .fixture
        .write()
        .policy_prefixes
        .get_mut(&prefix)
        .unwrap()
        .prefix
        .proof = Default::default();
    assert!(client
        .read_current_object_registration(&policy, &archived, HEIGHT)
        .await
        .is_err());
}
