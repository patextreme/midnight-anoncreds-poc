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
    tracing::info!("Current timestamp: {}", now);

    //---------------
    // Initialize VDR and roles
    //---------------
    let mut vdr = Vdr::new();
    let mut issuer = Issuer::new("did:midnight:mainnet:abc123")?;
    let mut prover = Prover::new()?;
    let mut verifier = Verifier::new();

    //---------------
    // Flow setup
    //---------------
    let schema_id = issuer.create_schema_and_publish(&mut vdr, "citizen-id", "0.1.0", &["name", "age"])?;
    let cred_def_id = issuer.create_credential_definition_and_publish(&mut vdr, &schema_id, "my-cred-def", true)?;
    let rev_reg_def_id = issuer.create_revocation_registry_and_publish(&mut vdr, &cred_def_id, "my-rev-reg", 128)?;

    issuer.publish_revocation_status_list(&mut vdr, &rev_reg_def_id, Some(now))?;

    //---------------
    // Issuance
    //---------------
    // Credential issuance flow
    let offer = issuer.create_credential_offer(&schema_id, &cred_def_id)?;
    let (request, metadata) = prover.create_credential_request(&vdr, &cred_def_id, &offer)?;

    let mut credential_values = MakeCredentialValues::default();
    credential_values.add_raw("name", "Alice")?;
    credential_values.add_raw("age", "21")?;

    let credential = issuer.issue_credential(&cred_def_id, &offer, &request, credential_values)?;
    prover.process_credential(credential, &metadata, &vdr, &cred_def_id)?;

    // Presentation flow
    verifier.fetch_required_objects_from_vdr(&vdr, &schema_id, &cred_def_id, &rev_reg_def_id)?;

    let pres_req = verifier.create_presentation_request("Citizen Proof", "1.0")?;
    let presentation = prover.create_presentation(&pres_req, &vdr)?;

    let valid = verifier.verify_presentation(&presentation, &pres_req)?;

    if valid {
        tracing::info!("Presentation verified successfully!");
    } else {
        tracing::error!("Presentation verification failed!");
    }

    Ok(())
}
