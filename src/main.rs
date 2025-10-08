use std::collections::HashMap;

use anoncreds::data_types::cred_def::CredentialDefinitionId;
use anoncreds::data_types::issuer_id::IssuerId;
use anoncreds::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use anoncreds::data_types::schema::SchemaId;
use anoncreds::tails::TailsFileWriter;
use anoncreds::types::*;
use anoncreds::{issuer, prover, verifier};
use chrono::Utc;
use serde_json::{from_value, json};
use tracing_subscriber;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let now: u64 = Utc::now().timestamp().try_into()?;
    tracing::info!("Tracing initialized. Current timestamp: {}", now);

    // -------------
    // IDs
    // -------------
    let issuer_id = IssuerId::new("did:midnight:mainnet:abc123")?;
    let schema_id = SchemaId::new("vdr://schemas/citizen-id?drf=midnight")?;
    let cred_def_id = CredentialDefinitionId::new("vdr://credential-definitions/citizen-id-0001?drf=midnight")?;
    let rev_reg_def_id = RevocationRegistryDefinitionId::new("vdr://revocation-registry-definitions/citizen-id-0001")?;
    let schema_id_clone = schema_id.clone();
    let cred_def_id_clone = cred_def_id.clone();
    let rev_reg_def_id_clone = rev_reg_def_id.clone();

    // -------------
    // schema
    // -------------
    let schema_attrs: &[&str] = &["name", "age"];
    let schema = issuer::create_schema("citizen-id", "0.1.0", issuer_id.clone(), schema_attrs.into())?;

    // -------------
    // credential definition
    // -------------
    let (cred_def, cred_def_priv, cred_def_correctness_proof) = issuer::create_credential_definition(
        schema_id.clone(),
        &schema,
        issuer_id,
        "my-cred-def",
        SignatureType::CL,
        CredentialDefinitionConfig {
            support_revocation: true,
        },
    )?;

    // -------------
    // revocation registry
    // -------------
    let mut tw = TailsFileWriter::new(None);
    let (rev_reg_def, rev_reg_def_priv) = issuer::create_revocation_registry_def(
        &cred_def,
        cred_def_id.clone(),
        "my-rev-reg",
        RegistryType::CL_ACCUM,
        128,
        &mut tw,
    )?;
    let rev_list = issuer::create_revocation_status_list(
        &cred_def,
        rev_reg_def_id,
        &rev_reg_def,
        &rev_reg_def_priv,
        true,
        Some(now),
    )?;

    // -------------
    // credential issuance
    // -------------
    let cred_offer =
        issuer::create_credential_offer(schema_id.clone(), cred_def_id.clone(), &cred_def_correctness_proof)?;

    let link_secret = prover::create_link_secret()?;

    let (cred_request, cred_request_metadata) =
        prover::create_credential_request(Some("entropy"), None, &cred_def, &link_secret, "my-secret", &cred_offer)?;

    let mut credential_values = MakeCredentialValues::default();
    credential_values.add_raw("name", "Alice")?;
    credential_values.add_raw("age", "21")?;

    let mut credential = issuer::create_credential(
        &cred_def,
        &cred_def_priv,
        &cred_offer,
        &cred_request,
        credential_values.into(),
        None,
    )?;

    prover::process_credential(&mut credential, &cred_request_metadata, &link_secret, &cred_def, None)?;

    // -------------
    // presentation
    // -------------

    // Create proof request
    let nonce = verifier::generate_nonce()?;

    let pres_req: PresentationRequest = from_value(json!({
        "nonce": nonce,
        "name": "Citizen Proof",
        "version": "1.0",
        "requested_attributes": {
            "name_attr": {
                "name": "name"
            },
            "age_attr": {
                "name": "age"
            }
        },
        "requested_predicates": {}
    }))?;

    // Prepare maps for prover and verifier
    let mut schemas = HashMap::new();
    schemas.insert(schema_id_clone, schema);

    let mut cred_defs = HashMap::new();
    cred_defs.insert(cred_def_id_clone, cred_def);

    let mut rev_reg_defs_map = HashMap::new();
    rev_reg_defs_map.insert(rev_reg_def_id_clone, rev_reg_def);

    let rev_status_lists = vec![rev_list];

    // Prover creates presentation
    let mut presented_credentials = PresentCredentials::default();
    let mut cred_builder = presented_credentials.add_credential(&credential, None, None);
    cred_builder.add_requested_attribute("name_attr", true);
    cred_builder.add_requested_attribute("age_attr", true);

    let presentation = prover::create_presentation(
        &pres_req,
        presented_credentials,
        None,
        &link_secret,
        &schemas,
        &cred_defs,
    )?;

    // Verifier verifies the presentation
    let valid = verifier::verify_presentation(
        &presentation,
        &pres_req,
        &schemas,
        &cred_defs,
        Some(&rev_reg_defs_map),
        Some(rev_status_lists),
        None,
    )?;

    if valid {
        tracing::info!("Presentation verified successfully!");
    } else {
        tracing::error!("Presentation verification failed!");
    }

    Ok(())
}
