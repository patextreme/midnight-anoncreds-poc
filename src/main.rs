use anoncreds::data_types::issuer_id::IssuerId;
use anoncreds::types::*;
use chrono::Utc;

mod issuer;
mod prover;
mod vdr;
mod verifier;

use issuer::Issuer;
use prover::Prover;
use vdr::Vdr;
use verifier::Verifier;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let now: u64 = Utc::now().timestamp().try_into()?;
    tracing::info!("Tracing initialized. Current timestamp: {}", now);

    // Initialize VDR and roles
    let mut vdr = Vdr::new();
    let issuer_id = IssuerId::new("did:midnight:mainnet:abc123")?;
    let mut issuer = Issuer::new(issuer_id)?;
    let mut prover = Prover::new()?;
    let mut verifier = Verifier::new();

    // Issuer creates and publishes schema
    let schema_id = issuer.create_schema_and_publish(&mut vdr, "citizen-id", "0.1.0", &["name", "age"])?;

    // Issuer creates and publishes credential definition
    let cred_def_id = issuer.create_credential_definition_and_publish(&mut vdr, &schema_id, "my-cred-def", true)?;

    // Issuer creates and publishes revocation registry
    let rev_reg_def_id = issuer.create_revocation_registry_and_publish(&mut vdr, &cred_def_id, "my-rev-reg", 128)?;

    // Issuer publishes revocation status list
    issuer.publish_revocation_status_list(&mut vdr, &rev_reg_def_id, Some(now))?;

    // Prover fetches credential definition from VDR
    prover.fetch_credential_definition_from_vdr(&vdr, &cred_def_id);

    // Credential issuance flow
    let offer = issuer.create_credential_offer(&schema_id, &cred_def_id)?;
    let cred_def = prover.get_cached_cred_defs().get(&cred_def_id).unwrap().try_clone()?;
    let (request, metadata) = prover.create_credential_request(&cred_def, &offer)?;

    let mut credential_values = MakeCredentialValues::default();
    credential_values.add_raw("name", "Alice")?;
    credential_values.add_raw("age", "21")?;

    let credential = issuer.issue_credential(&cred_def_id, &offer, &request, credential_values)?;
    prover.process_credential(credential, &metadata, &cred_def)?;

    // Presentation flow
    verifier.fetch_schema_from_vdr(&vdr, &schema_id);
    verifier.fetch_credential_definition_from_vdr(&vdr, &cred_def_id);
    verifier.fetch_revocation_registry_definition_from_vdr(&vdr, &rev_reg_def_id);

    let pres_req = verifier.create_presentation_request("Citizen Proof", "1.0")?;
    let presentation = prover.create_presentation(
        &pres_req,
        verifier.get_cached_schemas(),
        verifier.get_cached_cred_defs(),
    )?;

    let valid = verifier.verify_presentation(&presentation, &pres_req)?;

    if valid {
        tracing::info!("Presentation verified successfully!");
    } else {
        tracing::error!("Presentation verification failed!");
    }

    Ok(())
}
