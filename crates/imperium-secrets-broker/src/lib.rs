pub struct SecretsBroker {
    _vault: std::sync::Arc<imperium_secrets_vault::Vault>,
}

impl SecretsBroker {
    pub fn new(vault: std::sync::Arc<imperium_secrets_vault::Vault>) -> Self {
        Self { _vault: vault }
    }
}
