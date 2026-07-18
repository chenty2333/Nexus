// SPDX-License-Identifier: MPL-2.0

use core::cell::Cell;

use nexus_portal_abi::{
    BASE_PORTAL_CAPABILITIES, CapabilityOffer, CapabilityRequest, PortalCapabilities,
    PortalErrorCode, ProviderCapabilities, negotiate, negotiate_then,
};

fn offer() -> CapabilityOffer {
    CapabilityOffer {
        portal: BASE_PORTAL_CAPABILITIES | PortalCapabilities::CREATE_SCOPE,
        provider: ProviderCapabilities::EFFECT_CLOSURE
            | ProviderCapabilities::LOGICAL_REQUEST
            | ProviderCapabilities::SERVICE_REBIND,
    }
}

#[test]
fn optional_capabilities_intersect_while_required_capabilities_gate() {
    let request = CapabilityRequest {
        requested_portal: PortalCapabilities::CREATE_SCOPE | PortalCapabilities::QUERY_SCOPE,
        required_portal: PortalCapabilities::NEGOTIATE,
        requested_provider: ProviderCapabilities::LOGICAL_REQUEST
            | ProviderCapabilities::RETAINED_DEVICE,
        required_provider: ProviderCapabilities::EFFECT_CLOSURE,
    };
    let selected = negotiate(offer(), request).unwrap();
    assert_eq!(
        selected.portal,
        PortalCapabilities::CREATE_SCOPE
            | PortalCapabilities::QUERY_SCOPE
            | PortalCapabilities::NEGOTIATE
    );
    assert_eq!(
        selected.provider,
        ProviderCapabilities::LOGICAL_REQUEST | ProviderCapabilities::EFFECT_CLOSURE
    );
}

#[test]
fn missing_required_capabilities_are_exact_and_precede_mutation() {
    let request = CapabilityRequest {
        requested_portal: PortalCapabilities::all(),
        required_portal: PortalCapabilities::CREATE_SCOPE,
        requested_provider: ProviderCapabilities::all(),
        required_provider: ProviderCapabilities::RETAINED_DEVICE
            | ProviderCapabilities::PERSISTENT_HANDOFF,
    };
    let limited = CapabilityOffer {
        portal: BASE_PORTAL_CAPABILITIES,
        provider: ProviderCapabilities::EFFECT_CLOSURE,
    };
    let mutation_ran = Cell::new(false);
    let error = negotiate_then(limited, request, |_| mutation_ran.set(true)).unwrap_err();
    assert!(!mutation_ran.get());
    assert_eq!(error.code, PortalErrorCode::MissingRequiredCapability);
    assert_eq!(error.missing_portal, PortalCapabilities::CREATE_SCOPE);
    assert_eq!(
        error.missing_provider,
        ProviderCapabilities::RETAINED_DEVICE | ProviderCapabilities::PERSISTENT_HANDOFF
    );
}

#[test]
fn successful_negotiation_runs_mutation_once_with_selected_set() {
    let mutation_count = Cell::new(0_u32);
    let request = CapabilityRequest {
        requested_portal: PortalCapabilities::QUERY_SCOPE,
        required_portal: PortalCapabilities::NEGOTIATE,
        requested_provider: ProviderCapabilities::LOGICAL_REQUEST,
        required_provider: ProviderCapabilities::EFFECT_CLOSURE,
    };
    let result = negotiate_then(offer(), request, |selected| {
        mutation_count.set(mutation_count.get() + 1);
        selected
    })
    .unwrap();
    assert_eq!(mutation_count.get(), 1);
    assert!(result.portal.contains(PortalCapabilities::NEGOTIATE));
    assert!(
        result
            .provider
            .contains(ProviderCapabilities::EFFECT_CLOSURE)
    );
}

#[test]
fn unknown_capability_bits_fail_closed_before_mutation() {
    let clean_request = CapabilityRequest {
        requested_portal: PortalCapabilities::empty(),
        required_portal: PortalCapabilities::empty(),
        requested_provider: ProviderCapabilities::empty(),
        required_provider: ProviderCapabilities::empty(),
    };
    for bit in 8..u64::BITS {
        let mutation_ran = Cell::new(false);
        let unknown_offer = CapabilityOffer {
            portal: PortalCapabilities::from_bits_retain(1_u64 << bit),
            provider: ProviderCapabilities::empty(),
        };
        let error =
            negotiate_then(unknown_offer, clean_request, |_| mutation_ran.set(true)).unwrap_err();
        assert_eq!(
            error.code,
            PortalErrorCode::UnknownCapability,
            "portal bit={bit}"
        );
        assert!(!mutation_ran.get());
    }
    for bit in 8..u64::BITS {
        let unknown_request = CapabilityRequest {
            requested_portal: PortalCapabilities::empty(),
            required_portal: PortalCapabilities::empty(),
            requested_provider: ProviderCapabilities::from_bits_retain(1_u64 << bit),
            required_provider: ProviderCapabilities::empty(),
        };
        assert_eq!(
            negotiate(offer(), unknown_request).unwrap_err().code,
            PortalErrorCode::UnknownCapability,
            "provider bit={bit}"
        );
    }
}

#[test]
fn baseline_is_query_only_and_creation_is_explicitly_negotiated() {
    assert!(BASE_PORTAL_CAPABILITIES.contains(PortalCapabilities::QUERY_ABI));
    assert!(BASE_PORTAL_CAPABILITIES.contains(PortalCapabilities::NEGOTIATE));
    assert!(BASE_PORTAL_CAPABILITIES.contains(PortalCapabilities::QUERY_SCOPE));
    assert!(BASE_PORTAL_CAPABILITIES.contains(PortalCapabilities::QUERY_EFFECT));
    assert!(BASE_PORTAL_CAPABILITIES.contains(PortalCapabilities::QUERY_RECEIPT));
    assert!(!BASE_PORTAL_CAPABILITIES.contains(PortalCapabilities::CREATE_SCOPE));
}
