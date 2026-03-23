use fr_types::RecoverySourceKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source_kind: RecoverySourceKind,
}

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        name: "fr-fat",
        purpose: "Module boundary defined for phased implementation.",
        source_kind: RecoverySourceKind::Volume,
    }
}
