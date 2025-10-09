use std::collections::HashMap;

use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use anoncreds::data_types::rev_reg_def::{RevocationRegistryDefinition, RevocationRegistryDefinitionId};
use anoncreds::data_types::schema::{Schema, SchemaId};
use anoncreds::types::*;
use anoncreds::verifier;
use serde_json::json;

use crate::vdr::Vdr;

pub struct Verifier {}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier {
    pub fn new() -> Self {
        Self {}
    }

    pub fn create_presentation_request(&self, name: &str, version: &str) -> anyhow::Result<PresentationRequest> {
        let nonce = verifier::generate_nonce()?;
        let pres_req_value = json!({
            "nonce": nonce,
            "name": name,
            "version": version,
            "requested_attributes": {
                "name_attr": {
                    "name": "name"
                },
                "age_attr": {
                    "name": "age"
                }
            },
            "requested_predicates": {}
        });

        serde_json::from_value(pres_req_value)
            .map_err(|e| anyhow::anyhow!("Failed to create presentation request: {}", e))
    }

    fn fetch_schemas(vdr: &Vdr, presentation: &Presentation) -> anyhow::Result<HashMap<SchemaId, Schema>> {
        let mut schemas = HashMap::new();

        for identifier in &presentation.identifiers {
            if let Some(schema) = vdr.get_schema(&identifier.schema_id) {
                schemas.insert(identifier.schema_id.clone(), schema.clone());
            } else {
                return Err(anyhow::anyhow!("Schema not found: {}", identifier.schema_id));
            }
        }

        Ok(schemas)
    }

    fn fetch_credential_definitions(
        vdr: &Vdr,
        presentation: &Presentation,
    ) -> anyhow::Result<HashMap<CredentialDefinitionId, CredentialDefinition>> {
        let mut cred_defs = HashMap::new();

        for identifier in &presentation.identifiers {
            if let Some(cred_def) = vdr.get_credential_definition(&identifier.cred_def_id) {
                if let Ok(cloned_cred_def) = cred_def.try_clone() {
                    cred_defs.insert(identifier.cred_def_id.clone(), cloned_cred_def);
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to clone credential definition: {}",
                        identifier.cred_def_id
                    ));
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Credential definition not found: {}",
                    identifier.cred_def_id
                ));
            }
        }

        Ok(cred_defs)
    }

    fn fetch_revocation_registry_definitions(
        vdr: &Vdr,
        presentation: &Presentation,
    ) -> anyhow::Result<HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>> {
        let mut rev_reg_defs = HashMap::new();

        for identifier in &presentation.identifiers {
            if let Some(rev_reg_id) = &identifier.rev_reg_id
                && let Some(rev_reg_def) = vdr.get_revocation_registry_definition(rev_reg_id)
            {
                rev_reg_defs.insert(rev_reg_id.clone(), rev_reg_def.clone());
            }
        }

        Ok(rev_reg_defs)
    }

    pub fn verify_presentation(
        &self,
        vdr: &Vdr,
        presentation: &Presentation,
        pres_req: &PresentationRequest,
    ) -> anyhow::Result<bool> {
        let schemas = Self::fetch_schemas(vdr, presentation)?;
        let cred_defs = Self::fetch_credential_definitions(vdr, presentation)?;
        let rev_reg_defs = Self::fetch_revocation_registry_definitions(vdr, presentation)?;
        let rev_status_lists: Vec<RevocationStatusList> = Vec::new();

        Ok(verifier::verify_presentation(
            presentation,
            pres_req,
            &schemas,
            &cred_defs,
            if rev_reg_defs.is_empty() {
                None
            } else {
                Some(&rev_reg_defs)
            },
            Some(rev_status_lists),
            None,
        )?)
    }
}
