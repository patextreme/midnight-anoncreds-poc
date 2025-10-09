use std::collections::HashMap;

use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use anoncreds::data_types::rev_reg_def::{RevocationRegistryDefinition, RevocationRegistryDefinitionId};
use anoncreds::data_types::schema::{Schema, SchemaId};
use anoncreds::types::*;

pub struct Vdr {
    pub schemas: HashMap<SchemaId, Schema>,
    pub cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
    pub rev_reg_defs: HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>,
    pub rev_status_lists: HashMap<RevocationRegistryDefinitionId, RevocationStatusList>,
}

impl Default for Vdr {
    fn default() -> Self {
        Self::new()
    }
}

impl Vdr {
    pub fn new() -> Self {
        Self {
            schemas: HashMap::new(),
            cred_defs: HashMap::new(),
            rev_reg_defs: HashMap::new(),
            rev_status_lists: HashMap::new(),
        }
    }

    pub fn publish_schema(&mut self, schema_id: SchemaId, schema: Schema) {
        self.schemas.insert(schema_id, schema);
    }

    pub fn publish_credential_definition(
        &mut self,
        cred_def_id: CredentialDefinitionId,
        cred_def: CredentialDefinition,
    ) {
        self.cred_defs.insert(cred_def_id, cred_def);
    }

    pub fn publish_revocation_registry_definition(
        &mut self,
        rev_reg_def_id: RevocationRegistryDefinitionId,
        rev_reg_def: RevocationRegistryDefinition,
    ) {
        self.rev_reg_defs.insert(rev_reg_def_id, rev_reg_def);
    }

    pub fn publish_revocation_status_list(
        &mut self,
        rev_reg_def_id: RevocationRegistryDefinitionId,
        rev_status_list: RevocationStatusList,
    ) {
        self.rev_status_lists.insert(rev_reg_def_id, rev_status_list);
    }

    pub fn get_schema(&self, schema_id: &SchemaId) -> Option<&Schema> {
        self.schemas.get(schema_id)
    }

    pub fn get_credential_definition(&self, cred_def_id: &CredentialDefinitionId) -> Option<&CredentialDefinition> {
        self.cred_defs.get(cred_def_id)
    }

    pub fn get_revocation_registry_definition(
        &self,
        rev_reg_def_id: &RevocationRegistryDefinitionId,
    ) -> Option<&RevocationRegistryDefinition> {
        self.rev_reg_defs.get(rev_reg_def_id)
    }

    #[allow(dead_code)]
    pub fn get_revocation_status_list(
        &self,
        rev_reg_def_id: &RevocationRegistryDefinitionId,
    ) -> Option<&RevocationStatusList> {
        self.rev_status_lists.get(rev_reg_def_id)
    }
}
