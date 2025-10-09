use std::collections::HashMap;

use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use anoncreds::data_types::rev_reg_def::{RevocationRegistryDefinition, RevocationRegistryDefinitionId};
use anoncreds::data_types::schema::{Schema, SchemaId};
use anoncreds::types::*;
use anoncreds::verifier;
use serde_json::json;

use crate::vdr::Vdr;

pub struct Verifier {
    pub cached_schemas: HashMap<SchemaId, Schema>,
    pub cached_cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
    pub cached_rev_reg_defs: HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier {
    pub fn new() -> Self {
        Self {
            cached_schemas: HashMap::new(),
            cached_cred_defs: HashMap::new(),
            cached_rev_reg_defs: HashMap::new(),
        }
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

    pub fn verify_presentation(
        &self,
        presentation: &Presentation,
        pres_req: &PresentationRequest,
    ) -> anyhow::Result<bool> {
        let rev_reg_defs_map: HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition> = self
            .cached_rev_reg_defs
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let rev_status_lists: Vec<RevocationStatusList> = Vec::new();

        Ok(verifier::verify_presentation(
            presentation,
            pres_req,
            &self.cached_schemas,
            &self.cached_cred_defs,
            Some(&rev_reg_defs_map),
            Some(rev_status_lists),
            None,
        )?)
    }

    pub fn fetch_schema_from_vdr(&mut self, vdr: &Vdr, schema_id: &SchemaId) -> Option<&Schema> {
        if let Some(schema) = vdr.get_schema(schema_id) {
            self.cached_schemas.insert(schema_id.clone(), schema.clone());
            Some(self.cached_schemas.get(schema_id).unwrap())
        } else {
            None
        }
    }

    pub fn fetch_credential_definition_from_vdr(
        &mut self,
        vdr: &Vdr,
        cred_def_id: &CredentialDefinitionId,
    ) -> Option<&CredentialDefinition> {
        if let Some(cred_def) = vdr.get_credential_definition(cred_def_id) {
            if let Ok(cloned_cred_def) = cred_def.try_clone() {
                self.cached_cred_defs.insert(cred_def_id.clone(), cloned_cred_def);
                Some(self.cached_cred_defs.get(cred_def_id).unwrap())
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn fetch_revocation_registry_definition_from_vdr(
        &mut self,
        vdr: &Vdr,
        rev_reg_def_id: &RevocationRegistryDefinitionId,
    ) -> Option<&RevocationRegistryDefinition> {
        if let Some(rev_reg_def) = vdr.get_revocation_registry_definition(rev_reg_def_id) {
            self.cached_rev_reg_defs
                .insert(rev_reg_def_id.clone(), rev_reg_def.clone());
            Some(self.cached_rev_reg_defs.get(rev_reg_def_id).unwrap())
        } else {
            None
        }
    }

    pub fn get_cached_schemas(&self) -> &HashMap<SchemaId, Schema> {
        &self.cached_schemas
    }

    pub fn get_cached_cred_defs(&self) -> &HashMap<CredentialDefinitionId, CredentialDefinition> {
        &self.cached_cred_defs
    }

    #[allow(dead_code)]
    pub fn get_cached_rev_reg_defs(&self) -> &HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition> {
        &self.cached_rev_reg_defs
    }
}
