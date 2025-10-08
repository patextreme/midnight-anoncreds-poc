use anoncreds::data_types::cred_def::CredentialDefinitionId;
use anoncreds::data_types::issuer_id::IssuerId;
use anoncreds::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use anoncreds::data_types::schema::SchemaId;
use anoncreds::issuer;
use anoncreds::tails::TailsFileWriter;
use anoncreds::types::{CredentialDefinitionConfig, RegistryType, SignatureType};
use chrono::Utc;

fn main() -> anyhow::Result<()> {
    let now: u64 = Utc::now().timestamp().try_into()?;

    // -------------
    // IDs
    // -------------
    let issuer_id = IssuerId::new("did:midnight:mainnet:abc123")?;
    let schema_id = SchemaId::new("vdr://schemas/citizen-id?drf=midnight")?;
    let cred_def_id = CredentialDefinitionId::new("vdr://credential-definitions/citizen-id-0001?drf=midnight")?;
    let rev_reg_def_id = RevocationRegistryDefinitionId::new("vdr://revocation-registry-definitions/citizen-id-0001")?;

    // -------------
    // schema
    // -------------
    let schema_attrs: &[&str] = &["name", "age"];
    let schema = issuer::create_schema("citizen-id", "0.1.0", issuer_id.clone(), schema_attrs.into())?;

    // -------------
    // credential definition
    // -------------
    let (cred_def, cred_def_priv, cred_def_correctness) = issuer::create_credential_definition(
        schema_id,
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
        cred_def_id,
        "my-rev-reg",
        RegistryType::CL_ACCUM,
        2048,
        &mut tw,
    )?;
    let rev_list =
        issuer::create_revocation_status_list(&cred_def, rev_reg_def_id, &rev_reg_def, &rev_reg_def_priv, true, Some(now))?;

    println!("{:?}", rev_list);

    Ok(())
}
